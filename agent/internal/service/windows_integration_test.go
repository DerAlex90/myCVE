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

	"golang.org/x/sys/windows/svc"
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

// Verify real installer ACLs, upgrades and recovery without touching an existing installation.
func TestNativeWindowsInstallerTransaction(t *testing.T) {
	if os.Getenv("MYCVE_TEST_WINDOWS_SERVICE") != "1" {
		t.Skip("requires isolated elevated Windows runner")
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	if existing, err := manager.OpenService(Name); err == nil {
		existing.Close()
		manager.Disconnect()
		t.Skip("existing service must not be replaced")
	}
	manager.Disconnect()
	dir := t.TempDir()
	binary := filepath.Join(dir, "mycve-agent.exe")
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "../../cmd/mycve-agent")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %s %v", output, err)
	}
	delivered := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if json.NewDecoder(request.Body).Decode(&body) != nil {
			http.Error(writer, "invalid", 400)
			return
		}
		select {
		case delivered <- true:
		default:
		}
		json.NewEncoder(writer).Encode(map[string]any{"accepted": true, "snapshot_id": body["snapshot_id"]})
	}))
	defer server.Close()
	config := filepath.Join(dir, "source-config.json")
	data, _ := json.Marshal(map[string]any{"server_url": server.URL, "agent_id": "test-agent", "token": "mycve_agent_" + strings.Repeat("x", 48), "interval_seconds": 21600, "allow_insecure_localhost": true})
	if err := os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../deploy/windows/Install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	install := func(source string) error {
		cmd := exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-File", script, "-ConfigPath", config, "-BinaryPath", source)
		cmd.Env = append(os.Environ(), "ProgramData="+dir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("installer result: %s", output)
		}
		return err
	}
	destination := filepath.Join(dir, "myCVE-Agent", "mycve-agent.exe")
	defer func() {
		exec.Command(destination, "service", "stop").Run()
		exec.Command(destination, "service", "uninstall").Run()
	}()
	if err := install(binary); err != nil {
		t.Fatalf("initial installation: %v", err)
	}
	select {
	case <-delivered:
	case <-time.After(120 * time.Second):
		t.Fatal("installed service did not send inventory")
	}
	statePath := filepath.Join(dir, "myCVE-Agent", "state", "identity.json")
	// The identity filename is deliberately discovered from the real state directory.
	stateFiles, err := os.ReadDir(filepath.Dir(statePath))
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, entry := range stateFiles {
		if !entry.IsDir() {
			data, _ := os.ReadFile(filepath.Join(filepath.Dir(statePath), entry.Name()))
			before[entry.Name()] = string(data)
		}
	}
	if len(before) == 0 {
		t.Fatal("device state was not persisted")
	}
	if err := install(binary); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	fakeSource := filepath.Join(dir, "broken.go")
	fakeCode := []byte("package main\nimport \"os\"\nfunc main(){if len(os.Args)>1 && os.Args[1]==\"check\" {return}; os.Exit(23)}\n")
	if err := os.WriteFile(fakeSource, fakeCode, 0600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "broken.exe")
	if output, err := exec.Command("go", "build", "-o", fake, fakeSource).CombinedOutput(); err != nil {
		t.Fatalf("fake build: %s %v", output, err)
	}
	if err := install(fake); err == nil {
		t.Fatal("broken replacement must fail")
	}
	original, _ := os.ReadFile(binary)
	restored, _ := os.ReadFile(destination)
	if string(original) != string(restored) {
		t.Fatal("rollback did not restore original executable")
	}
	manager, err = mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(Name)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil || status.State != svc.Running {
		t.Fatalf("original service is not running: %v %v", status, err)
	}
	for name, data := range before {
		if strings.Contains(name, "identity") || strings.Contains(name, "device") {
			current, _ := os.ReadFile(filepath.Join(filepath.Dir(statePath), name))
			if string(current) != data {
				t.Fatal("device identity changed during upgrade")
			}
		}
	}
	aclScript := filepath.Join(dir, "check-acl.ps1")
	aclCode := []byte(`param([string]$Path)
$acl=Get-Acl -LiteralPath $Path
if(-not $acl.AreAccessRulesProtected){exit 1}
$allowed=@('S-1-5-18','S-1-5-32-544')
foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.IdentityReference.Value -notin $allowed){exit 2}}
`)
	if err := os.WriteFile(aclScript, aclCode, 0600); err != nil {
		t.Fatal(err)
	}
	aclCheck := exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-File", aclScript, filepath.Join(dir, "myCVE-Agent", "config.json"))
	if output, err := aclCheck.CombinedOutput(); err != nil {
		t.Fatalf("configuration ACL: %s %v", output, err)
	}
}
