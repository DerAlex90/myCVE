package collector

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

func parseWindowsAppx(data []byte) protocol.Collector {
	var entries []struct {
		Name            string
		Version         string
		Architecture    string
		Publisher       string
		PackageFullName string
	}
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &entries); err != nil {
		return failed("windows_appx", errors.New("Appx JSON could not be processed"))
	}
	result := protocol.Collector{ID: "windows_appx", Complete: true, Packages: []protocol.Package{}}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.Name == "" || entry.Version == "" {
			return failed("windows_appx", errors.New("Appx inventory record has no name or version"))
		}
		id := StableID(entry.Name + ":" + entry.Architecture + ":" + entry.Publisher + ":" + entry.Version)
		if seen[id] {
			continue
		}
		seen[id] = true
		result.Packages = append(result.Packages, protocol.Package{ID: id, Name: entry.Name, Version: entry.Version, VersionSource: "Appx.Version", Publisher: entry.Publisher, Architecture: entry.Architecture})
	}
	return result
}
