// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DerAlex90/myCVE/agent/internal/client"
	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

type transport struct {
	fail     bool
	requests [][]byte
}

func (fake *transport) Upload(_ context.Context, body []byte) (protocol.Acknowledgement, error) {
	fake.requests = append(fake.requests, append([]byte(nil), body...))
	if fake.fail {
		return protocol.Acknowledgement{}, errors.New("offline")
	}
	var report protocol.Inventory
	json.Unmarshal(body, &report)
	return protocol.Acknowledgement{Accepted: true, SnapshotID: report.SnapshotID}, nil
}

func TestFailedTransferSurvivesRestartAndRetriesExactReport(t *testing.T) {
	dir := t.TempDir()
	fake := &transport{fail: true}
	collect := func(_ context.Context, id string, _ []string) (protocol.Inventory, error) {
		reportID, _ := protocol.UUID()
		return protocol.Inventory{SchemaVersion: 1, DeviceID: id, SnapshotID: reportID, CollectedAt: time.Now().UTC()}, nil
	}
	runner := Runner{Config: client.Config{StateDir: dir}, Uploader: fake, Collect: collect}
	if runner.Cycle(context.Background()) == nil {
		t.Fatal("expected offline error")
	}
	first, err := os.ReadFile(filepath.Join(dir, "pending.json"))
	if err != nil {
		t.Fatal("pending report not persisted")
	}
	deviceID, err := DeviceID(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake.fail = false
	restarted := Runner{Config: runner.Config, Uploader: fake, Collect: collect}
	if err := restarted.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.requests) != 3 || string(fake.requests[1]) != string(first) {
		t.Fatal("persisted report was not retried unchanged")
	}
	if _, err := os.Stat(filepath.Join(dir, "pending.json")); !os.IsNotExist(err) {
		t.Fatal("acknowledged pending report not removed")
	}
	if after, _ := DeviceID(dir); deviceID != after {
		t.Fatal("device identity changed after restart")
	}
}

func TestConcurrentProcessesCannotShareStateDirectory(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Lock(dir); err == nil {
		other()
		unlock()
		t.Fatal("second process lock succeeded")
	}
	unlock()
	again, err := Lock(dir)
	if err != nil {
		t.Fatal("lock was not released")
	}
	again()
}

func TestBrokenIdentityIsNotSilentlyReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := AtomicWrite(filepath.Join(dir, "device-id"), []byte("broken")); err != nil {
		t.Fatal(err)
	}
	if _, err := DeviceID(dir); err == nil {
		t.Fatal("corrupt identity must not create a second device")
	}
}
