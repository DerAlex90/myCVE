//go:build linux

package collector

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

func platformCollect(ctx context.Context, host *protocol.Host) []protocol.Collector {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		data, _ = os.ReadFile("/usr/lib/os-release")
	}
	info := readOSRelease(string(data))
	host.Name, host.Version = info["PRETTY_NAME"], info["VERSION_ID"]
	host.Distribution, host.DistributionVersion = info["ID"], info["VERSION_ID"]
	if kernel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		host.Kernel = strings.TrimSpace(string(kernel))
	}
	if _, err := os.Stat("/lib/apk/db/installed"); err == nil {
		data, err := os.ReadFile("/lib/apk/db/installed")
		if err != nil {
			return []protocol.Collector{failed("apk", err)}
		}
		packages, err := parseAPK(string(data), host.Distribution, host.DistributionVersion)
		if err != nil {
			return []protocol.Collector{failed("apk", err)}
		}
		return []protocol.Collector{{ID: "apk", Complete: true, Packages: packages}}
	}
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		data, err := command(ctx, "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n")
		if err != nil {
			return []protocol.Collector{failed("dpkg", err)}
		}
		packages, err := parseDPKG(string(data), host.Distribution, host.DistributionVersion)
		if err != nil {
			return []protocol.Collector{failed("dpkg", err)}
		}
		return []protocol.Collector{{ID: "dpkg", Complete: true, Packages: packages}}
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		data, err := command(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\n")
		if err != nil {
			return []protocol.Collector{failed("rpm", err)}
		}
		packages, err := parseRPM(string(data), host.Distribution, host.DistributionVersion)
		if err != nil {
			return []protocol.Collector{failed("rpm", err)}
		}
		return []protocol.Collector{{ID: "rpm", Complete: true, Packages: packages}}
	}
	return []protocol.Collector{failed("system", errors.New("no supported dpkg, RPM or APK inventory found"))}
}
