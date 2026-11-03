// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ServerURL              string   `json:"server_url"`
	AgentID                string   `json:"agent_id"`
	Token                  string   `json:"token"`
	IntervalSeconds        int      `json:"interval_seconds"`
	AllowInsecureLocalhost bool     `json:"allow_insecure_localhost"`
	CAFile                 string   `json:"ca_file,omitempty"`
	StateDir               string   `json:"state_dir,omitempty"`
	SBOMPaths              []string `json:"sbom_paths,omitempty"`
}

func LoadConfig(path, stateOverride string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("configuration could not be read: %w", err)
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("invalid configuration JSON or unknown field")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return Config{}, err
	}
	if stateOverride != "" {
		config.StateDir = stateOverride
	}
	if config.StateDir == "" {
		config.StateDir = filepath.Join(dir, "state")
	}
	if !filepath.IsAbs(config.StateDir) {
		config.StateDir = filepath.Join(dir, config.StateDir)
	}
	if config.CAFile != "" && !filepath.IsAbs(config.CAFile) {
		config.CAFile = filepath.Join(dir, config.CAFile)
	}
	for i, path := range config.SBOMPaths {
		if !filepath.IsAbs(path) {
			config.SBOMPaths[i] = filepath.Join(dir, path)
		}
	}
	return config, nil
}

func (config *Config) Validate() error {
	parsed, err := url.Parse(config.ServerURL)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("server_url must be an HTTPS URL without credentials, query or fragment")
	}
	local := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && local && config.AllowInsecureLocalhost) {
		return errors.New("HTTPS is required; local HTTP needs allow_insecure_localhost=true")
	}
	config.ServerURL = strings.TrimRight(config.ServerURL, "/")
	if config.AgentID == "" || len(config.AgentID) > 100 {
		return errors.New("agent_id is required")
	}
	if !strings.HasPrefix(config.Token, "mycve_agent_") || len(config.Token) < 40 || len(config.Token) > 200 {
		return errors.New("a device-scoped agent token is required")
	}
	if config.IntervalSeconds == 0 {
		config.IntervalSeconds = 21600
	}
	if config.IntervalSeconds < 300 || config.IntervalSeconds > 604800 {
		return errors.New("interval_seconds must be between 300 and 604800")
	}
	if len(config.SBOMPaths) > 16 {
		return errors.New("at most 16 SBOM paths may be configured")
	}
	return nil
}
