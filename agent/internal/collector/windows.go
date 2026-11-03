//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
	"golang.org/x/sys/windows/registry"
)

func value(key registry.Key, name string) string {
	text, _, _ := key.GetStringValue(name)
	return strings.TrimSpace(text)
}
func bounded(value string, maximum int) string {
	runes := []rune(value)
	if len(runes) > maximum {
		return string(runes[:maximum])
	}
	return value
}

func platformCollect(ctx context.Context, host *protocol.Host) []protocol.Collector {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		host.Name = value(key, "ProductName")
		host.Version = value(key, "DisplayVersion")
		if host.Version == "" {
			host.Version = value(key, "ReleaseId")
		}
		host.Build = value(key, "CurrentBuildNumber")
		ubr, _, err := key.GetIntegerValue("UBR")
		if err == nil {
			host.Build += "." + strconv.FormatUint(ubr, 10)
		}
		key.Close()
	}
	installed := protocol.Collector{ID: "windows_registry", Complete: true, Packages: []protocol.Package{}}
	var failures []string
	metadataBudget := 256
	read := func(root registry.Key, scope, path, architecture string, view uint32) {
		parent, err := registry.OpenKey(root, path, registry.READ|view)
		if errors.Is(err, registry.ErrNotExist) {
			return
		}
		if err != nil {
			failures = append(failures, scope+": registry access unavailable")
			return
		}
		defer parent.Close()
		names, err := parent.ReadSubKeyNames(-1)
		if err != nil {
			failures = append(failures, scope+": registry enumeration incomplete")
			return
		}
		for _, name := range names {
			child, err := registry.OpenKey(parent, name, registry.QUERY_VALUE|view)
			if err != nil {
				failures = append(failures, scope+": application entry unreadable")
				continue
			}
			displayName, publisher := value(child, "DisplayName"), value(child, "Publisher")
			if displayName == "" {
				child.Close()
				continue
			}
			budget := &metadataBudget
			if scope == "user" {
				// An unprivileged user controls these paths; SYSTEM reads registry metadata only.
				noFileLookups := 0
				budget = &noFileLookups
			}
			version, versionSource := registryVersion(ctx, child, displayName, publisher, budget)
			child.Close()
			installed.Packages = append(installed.Packages, protocol.Package{ID: StableID(scope + ":" + architecture + ":" + path + ":" + name), Name: bounded(displayName, 500), Version: bounded(version, 300), VersionSource: versionSource, Publisher: bounded(publisher, 300), Architecture: architecture})
		}
	}
	nativeArchitecture := host.Architecture
	if nativeArchitecture == "amd64" {
		nativeArchitecture = "x64"
	}
	path := `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	read(registry.LOCAL_MACHINE, "machine", path, nativeArchitecture, registry.WOW64_64KEY)
	read(registry.LOCAL_MACHINE, "machine", path, "x86", registry.WOW64_32KEY)
	users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		names, err := users.ReadSubKeyNames(-1)
		users.Close()
		if err != nil {
			failures = append(failures, "loaded user hives could not be enumerated")
		}
		for _, sid := range names {
			if !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "_Classes") {
				continue
			}
			read(registry.USERS, "user", sid+`\`+path, nativeArchitecture, registry.WOW64_64KEY)
			read(registry.USERS, "user", sid+`\`+path, "x86", registry.WOW64_32KEY)
		}
	} else {
		failures = append(failures, "loaded user hives are not accessible")
	}
	if len(failures) > 0 {
		installed.Complete = false
		installed.Error = fmt.Sprintf("Registry inventory partial (%d unreadable areas); previous entries retained", len(failures))
	}
	// The command is fixed; inventory strings are never interpolated into executable code.
	script := `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); ConvertTo-Json -InputObject @(Get-AppxPackage -AllUsers | Select-Object Name,@{n='Version';e={$_.Version.ToString()}},@{n='Architecture';e={$_.Architecture.ToString()}},Publisher,PackageFullName) -Compress`
	data, err := command(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	appx := protocol.Collector{}
	if err != nil {
		appx = failed("windows_appx", errors.New("Appx inventory unavailable; requires an account permitted to enumerate all users"))
	} else {
		appx = parseWindowsAppx(data)
	}
	return []protocol.Collector{installed, appx}
}
