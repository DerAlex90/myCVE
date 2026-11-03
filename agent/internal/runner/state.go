package runner

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

func AtomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".mycve-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func DeviceID(dir string) (string, error) {
	path := filepath.Join(dir, "device-id")
	data, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`).MatchString(id) {
			return "", errors.New("invalid persistent device identity")
		}
		return id, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	id, err := protocol.UUID()
	if err != nil {
		return "", err
	}
	return id, AtomicWrite(path, []byte(id+"\n"))
}
