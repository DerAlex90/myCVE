package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

type limitBuffer struct{ bytes.Buffer }

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > protocol.MaxBytes {
		return 0, errors.New("command output exceeds 10 MB")
	}
	return b.Buffer.Write(p)
}

func command(ctx context.Context, program string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var stdout, stderr limitBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s could not be read: %w", program, err)
	}
	return stdout.Bytes(), nil
}

func StableID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func failed(id string, err error) protocol.Collector {
	text := err.Error()
	if len(text) > 1800 {
		text = text[:1800]
	}
	return protocol.Collector{ID: id, Complete: false, Error: text, Packages: []protocol.Package{}}
}

func Collect(ctx context.Context, deviceID string, sbomPaths []string) (protocol.Inventory, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return protocol.Inventory{}, err
	}
	host := protocol.Host{Hostname: hostname, OS: runtime.GOOS, Architecture: runtime.GOARCH}
	collectors := platformCollect(ctx, &host)
	for _, path := range sbomPaths {
		collectors = append(collectors, collectSBOM(path))
	}
	total := 0
	for i := range collectors {
		if collectors[i].Packages == nil {
			collectors[i].Packages = []protocol.Package{}
		}
		remaining := protocol.MaxPackages - total
		if len(collectors[i].Packages) > remaining {
			collectors[i].Packages = collectors[i].Packages[:remaining]
			collectors[i].Complete = false
			collectors[i].Error = "Package limit exceeded; no removals will be applied for this source"
		}
		total += len(collectors[i].Packages)
	}
	if ctx.Err() != nil {
		return protocol.Inventory{}, ctx.Err()
	}
	id, err := protocol.UUID()
	if err != nil {
		return protocol.Inventory{}, err
	}
	return protocol.Inventory{SchemaVersion: 1, SnapshotID: id, DeviceID: deviceID, CollectedAt: time.Now().UTC(), AgentVersion: protocol.Version, Host: host, Collectors: collectors}, nil
}

func readOSRelease(text string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(strings.TrimSpace(key), "#") {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), "\"'")
	}
	return values
}
