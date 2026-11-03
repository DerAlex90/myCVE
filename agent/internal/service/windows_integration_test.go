//go:build windows

// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

// Explicitly enabled on an isolated elevated Windows CI runner. No existing service is touched.
func TestNativeWindowsServiceLifecycle(t *testing.T) {
	if os.Getenv("MYCVE_TEST_WINDOWS_SERVICE") != "1" {
		t.Skip("requires isolated elevated Windows runner")
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatalf("service manager unavailable: %v", err)
	}
	if existing, err := manager.OpenService(Name); err == nil {
		existing.Close()
		manager.Disconnect()
		t.Skip("an existing myCVE service must not be replaced by a test")
	}
	manager.Disconnect()
	dir := t.TempDir()
	binary := filepath.Join(dir, "mycve-agent.exe")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "../../cmd/mycve-agent")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %s %v", output, err)
	}
	received := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var report struct {
			SnapshotID string `json:"snapshot_id"`
			DeviceID   string `json:"device_id"`
			Host       struct {
				OS string `json:"os"`
			} `json:"host"`
		}
		if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
			http.Error(writer, "invalid report", 400)
			return
		}
		select {
		case received <- report.Host.OS == "windows" && report.DeviceID != "":
		default:
		}
		json.NewEncoder(writer).Encode(map[string]any{"accepted": true, "snapshot_id": report.SnapshotID})
	}))
	defer server.Close()
	config := map[string]any{"server_url": server.URL, "agent_id": "test-agent", "token": "mycve_agent_" + strings.Repeat("x", 48), "interval_seconds": 21600, "allow_insecure_localhost": true, "state_dir": filepath.Join(dir, "state")}
	data, _ := json.Marshal(config)
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func(action string) error {
		command := exec.Command(binary, "service", action, "--config", configPath)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Logf("service %s failed: %s", action, output)
		}
		return err
	}
	if err := invoke("install"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := invoke("stop"); err != nil {
			t.Error(err)
		}
		if err := invoke("uninstall"); err != nil {
			t.Error(err)
		}
	}()
	if err := invoke("start"); err != nil {
		t.Fatal(err)
	}
	select {
	case correct := <-received:
		if !correct {
			t.Fatal("Windows service report has no valid host identity")
		}
	case <-time.After(120 * time.Second):
		t.Fatal("Windows service did not send inventory")
	}
}
