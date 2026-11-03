// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const Version = "0.4.0"
const Copyright = "Copyright (c) 2026 Alexander Speka (DerAlex90)"
const LicenseID = "LicenseRef-myCVE-Attribution-1.0"
const MaxBytes = 10_000_000
const MaxPackages = 10000

type Host struct {
	Hostname            string `json:"hostname"`
	OS                  string `json:"os"`
	Architecture        string `json:"architecture"`
	Name                string `json:"name,omitempty"`
	Version             string `json:"version,omitempty"`
	Build               string `json:"build,omitempty"`
	Kernel              string `json:"kernel,omitempty"`
	Distribution        string `json:"distribution,omitempty"`
	DistributionVersion string `json:"distribution_version,omitempty"`
}

type Package struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       string `json:"version,omitempty"`
	Publisher     string `json:"publisher,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
	Ecosystem     string `json:"ecosystem,omitempty"`
	PURL          string `json:"purl,omitempty"`
	CPE           string `json:"cpe,omitempty"`
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
	VersionSource string `json:"version_source,omitempty"`
}

type Collector struct {
	ID       string    `json:"id"`
	Complete bool      `json:"complete"`
	Error    string    `json:"error,omitempty"`
	Packages []Package `json:"packages"`
}

type Inventory struct {
	SchemaVersion int         `json:"schema_version"`
	SnapshotID    string      `json:"snapshot_id"`
	DeviceID      string      `json:"device_id"`
	CollectedAt   time.Time   `json:"collected_at"`
	AgentVersion  string      `json:"agent_version"`
	Host          Host        `json:"host"`
	Collectors    []Collector `json:"collectors"`
}

type Acknowledgement struct {
	Accepted          bool   `json:"accepted"`
	Duplicate         bool   `json:"duplicate"`
	Stale             bool   `json:"stale"`
	SnapshotID        string `json:"snapshot_id"`
	Partial           bool   `json:"partial"`
	NextReportSeconds int    `json:"next_report_seconds"`
}

func UUID() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	data[6] = (data[6] & 0x0f) | 0x40
	data[8] = (data[8] & 0x3f) | 0x80
	value := hex.EncodeToString(data[:])
	return value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:], nil
}
