// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package collector

import (
	"github.com/DerAlex90/myCVE/agent/internal/protocol"
	"testing"
)

func TestKernelImagesAndDevelopmentPackagesRemainDistinct(t *testing.T) {
	packages := annotateLinux([]protocol.Package{
		{Name: "linux-libc-dev"},
		{Name: "linux-headers-6.1.0-30-amd64"},
		{Name: "proxmox-kernel-6.8.12-2-pve-signed"},
		{Name: "kernel-core", Version: "0:6.12.0-100.el10", Architecture: "x86_64"},
		{Name: "libssl3"},
	})
	if packages[0].ComponentType != "development" || packages[1].ComponentType != "development" {
		t.Fatal("headers must not be runtime packages")
	}
	if packages[2].KernelRelease != "6.8.12-2-pve" || packages[3].KernelRelease != "6.12.0-100.el10.x86_64" {
		t.Fatal("exact installed image releases missing")
	}
	if packages[4].ComponentType != "runtime" || packages[4].KernelRelease != "" {
		t.Fatal("regular binary package classification changed")
	}
}
