package client

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configFor(url string) Config {
	return Config{ServerURL: url, AgentID: "agent-id", Token: "mycve_agent_" + strings.Repeat("x", 48), IntervalSeconds: 21600}
}

func TestTransportRequiresTLSOrExplicitLoopback(t *testing.T) {
	for _, url := range []string{"http://example.com", "http://192.168.1.10", "https://user:password@example.com", "https://example.com?token=secret", "ftp://example.com"} {
		config := configFor(url)
		config.AllowInsecureLocalhost = true
		if config.Validate() == nil {
			t.Fatalf("insecure URL accepted: %s", url)
		}
	}
	config := configFor("http://127.0.0.1:8000")
	if config.Validate() == nil {
		t.Fatal("loopback HTTP must be explicit")
	}
	config.AllowInsecureLocalhost = true
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestUploadScopesCredentialsAndVerifiesAcknowledgement(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/agent/inventory" || request.Header.Get("Authorization") != "Bearer mycve_agent_"+strings.Repeat("x", 48) || request.Header.Get("X-MyCVE-Agent-ID") != "agent-id" {
			t.Error("incorrect request scope")
		}
		data, _ := io.ReadAll(request.Body)
		if string(data) != `{"snapshot_id":"report"}` {
			t.Error("report bytes changed")
		}
		json.NewEncoder(writer).Encode(map[string]any{"accepted": true, "snapshot_id": "report"})
	}))
	defer server.Close()
	client, err := New(configFor(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.transport = server.Client()
	if _, err := client.Upload(context.Background(), []byte(`{"snapshot_id":"report"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestClientNeverForwardsDeviceTokenOnRedirect(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls++ }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	config := configFor(origin.URL)
	config.AllowInsecureLocalhost = true
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Upload(context.Background(), []byte(`{"snapshot_id":"report"}`)); err == nil {
		t.Fatal("redirect must fail")
	}
	if targetCalls != 0 {
		t.Fatal("credentials were forwarded to another origin")
	}
}

func TestMismatchedAcknowledgementAndUntrustedCertificateFail(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		json.NewEncoder(writer).Encode(map[string]any{"accepted": true, "snapshot_id": "different"})
	}))
	defer server.Close()
	client, err := New(configFor(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Upload(context.Background(), []byte(`{"snapshot_id":"report"}`)); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	client.transport = server.Client()
	if _, err := client.Upload(context.Background(), []byte(`{"snapshot_id":"report"}`)); err == nil {
		t.Fatal("wrong report was acknowledged")
	}
}

func TestCustomCAAddsTrustWithoutDisablingCertificateVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		json.NewEncoder(writer).Encode(map[string]any{"accepted": true, "snapshot_id": "report"})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "organization-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	config := configFor(server.URL)
	config.CAFile = path
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Upload(context.Background(), []byte(`{"snapshot_id":"report"}`)); err != nil {
		t.Fatal(err)
	}
	if client.transport.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS verification was disabled")
	}
}
