// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package collector

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

type bomComponent struct {
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	CPE        string         `json:"cpe"`
	Ref        string         `json:"bom-ref"`
	Components []bomComponent `json:"components"`
}

func collectSBOM(path string) protocol.Collector {
	absolute, err := filepath.Abs(path)
	id := "sbom:" + StableID(absolute)[:16]
	if err != nil {
		return failed(id, errors.New("SBOM path could not be resolved"))
	}
	info, err := os.Stat(path)
	if err != nil {
		return failed(id, errors.New("configured SBOM could not be read"))
	}
	if info.Size() > protocol.MaxBytes {
		return failed(id, errors.New("SBOM exceeds 10 MB"))
	}
	file, err := os.Open(path)
	if err != nil {
		return failed(id, errors.New("configured SBOM could not be read"))
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, protocol.MaxBytes+1))
	if err != nil || len(data) > protocol.MaxBytes {
		return failed(id, errors.New("SBOM could not be read within 10 MB limit"))
	}
	return parseSBOM(id, data)
}

func parseSBOM(id string, data []byte) protocol.Collector {
	var bom struct {
		Format     string         `json:"bomFormat"`
		Spec       string         `json:"specVersion"`
		Components []bomComponent `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		return failed(id, errors.New("invalid SBOM JSON"))
	}
	if bom.Format != "CycloneDX" {
		return failed(id, errors.New("CycloneDX JSON 1.4-1.7 required"))
	}
	switch bom.Spec {
	case "1.4", "1.5", "1.6", "1.7":
	default:
		return failed(id, errors.New("unsupported CycloneDX JSON version"))
	}
	result := protocol.Collector{ID: id, Complete: true, Packages: []protocol.Package{}}
	seen := map[string]protocol.Package{}
	var walk func([]bomComponent, int) error
	walk = func(items []bomComponent, depth int) error {
		if depth > 30 {
			return errors.New("SBOM nesting exceeds limit")
		}
		for _, item := range items {
			if item.Name == "" {
				return errors.New("SBOM component has no name")
			}
			key := item.Ref
			if key == "" {
				key = StableID(item.Name + "\x00" + item.Version + "\x00" + item.PURL + "\x00" + item.CPE)
			}
			candidate := protocol.Package{ID: StableID(key), Name: item.Name, Version: item.Version, PURL: item.PURL, CPE: item.CPE}
			previous, exists := seen[key]
			if exists && previous != candidate {
				return errors.New("conflicting SBOM component references; prior inventory retained")
			}
			if !exists {
				result.Packages = append(result.Packages, candidate)
				seen[key] = candidate
			}
			if len(result.Packages) > protocol.MaxPackages {
				return errors.New("SBOM package limit exceeded")
			}
			if err := walk(item.Components, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(bom.Components, 0); err != nil {
		return failed(id, err)
	}
	if len(result.Packages) == 0 {
		return failed(id, errors.New("SBOM has no components; existing inventory retained"))
	}
	return result
}
