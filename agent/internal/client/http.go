// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

type HTTPClient struct {
	config    Config
	transport *http.Client
}

func New(config Config) (*HTTPClient, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if config.CAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		data, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, errors.New("configured CA file could not be read")
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("configured CA file contains no certificate")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &HTTPClient{config: config, transport: &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (client *HTTPClient) Close() { client.transport.CloseIdleConnections() }

func (client *HTTPClient) Upload(ctx context.Context, payload []byte) (protocol.Acknowledgement, error) {
	var ack protocol.Acknowledgement
	if len(payload) > protocol.MaxBytes {
		return ack, errors.New("inventory exceeds 10 MB")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.config.ServerURL+"/api/agent/inventory", bytes.NewReader(payload))
	if err != nil {
		return ack, err
	}
	request.Header.Set("Authorization", "Bearer "+client.config.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "myCVE-Agent/"+protocol.Version)
	request.Header.Set("X-MyCVE-Agent-ID", client.config.AgentID)
	response, err := client.transport.Do(request)
	if err != nil {
		return ack, fmt.Errorf("inventory connection failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ack, fmt.Errorf("inventory rejected (HTTP %d); verify server, device registration and collector configuration", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 {
		return ack, errors.New("invalid server acknowledgement")
	}
	if err := json.Unmarshal(data, &ack); err != nil {
		return ack, errors.New("invalid server acknowledgement JSON")
	}
	if !ack.Accepted && !ack.Stale {
		return ack, errors.New("server did not accept inventory")
	}
	var sent struct {
		SnapshotID string `json:"snapshot_id"`
	}
	if err := json.Unmarshal(payload, &sent); err != nil {
		return ack, errors.New("invalid pending inventory")
	}
	if ack.SnapshotID != sent.SnapshotID {
		return ack, errors.New("server acknowledged a different inventory; pending report retained")
	}
	return ack, nil
}
