// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package collector

import (
	"regexp"
	"strings"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

var kernelImage = regexp.MustCompile(`^(?:linux-image|pve-kernel|proxmox-kernel)-(\d.+)$`)

func annotateLinux(packages []protocol.Package) []protocol.Package {
	for index := range packages {
		item := &packages[index]
		name := strings.Split(strings.ToLower(item.Name), ":")[0]
		item.ComponentType = "runtime"
		if strings.HasSuffix(name, "-dev") || strings.HasSuffix(name, "-devel") || strings.Contains(name, "-headers") {
			item.ComponentType = "development"
		}
		if image := kernelImage.FindStringSubmatch(name); image != nil {
			item.KernelRelease = strings.TrimSuffix(strings.TrimSuffix(image[1], "-signed"), "-unsigned")
		}
		if (name == "kernel" || name == "kernel-core" || name == "kernel-rt-core") && item.Version != "" && item.Architecture != "" {
			version := item.Version
			if colon := strings.IndexByte(version, ':'); colon >= 0 {
				version = version[colon+1:]
			}
			item.KernelRelease = version + "." + item.Architecture
		}
	}
	return packages
}
