package collector

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/DerAlex90/myCVE/agent/internal/protocol"
)

func packagePURL(kind, namespace, name, version, architecture, distro string) string {
	values := url.Values{}
	if architecture != "" {
		values.Set("arch", architecture)
	}
	if distro != "" {
		values.Set("distro", distro)
	}
	value := "pkg:" + kind + "/" + url.PathEscape(namespace) + "/" + url.PathEscape(name) + "@" + url.PathEscape(version)
	if len(values) > 0 {
		value += "?" + values.Encode()
	}
	return value
}

func parseDPKG(text, distro, distributionVersion string) ([]protocol.Package, error) {
	packages := []protocol.Package{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 6 {
			return nil, errors.New("incomplete dpkg record")
		}
		if !strings.HasPrefix(parts[5], "ii") {
			continue
		}
		name := strings.SplitN(parts[0], ":", 2)[0]
		if name == "" || parts[1] == "" {
			return nil, errors.New("dpkg record has no name or version")
		}
		sourceName, sourceVersion := parts[3], parts[4]
		if sourceName == "" {
			sourceName = name
		}
		if sourceVersion == "" {
			sourceVersion = parts[1]
		}
		item := protocol.Package{ID: name + ":" + parts[2], Name: name, Version: parts[1], Architecture: parts[2], Publisher: distro, SourceName: sourceName, SourceVersion: sourceVersion}
		if distro != "" {
			item.PURL = packagePURL("deb", distro, sourceName, sourceVersion, parts[2], distro+"-"+distributionVersion)
		}
		// OSV Debian tracks source packages and the source version, not the binary version.
		if distro == "debian" && distributionVersion != "" {
			item.Ecosystem = "Debian:" + distributionVersion
		}
		packages = append(packages, item)
	}
	return packages, nil
}

func parseRPM(text, distro, distributionVersion string) ([]protocol.Package, error) {
	packages := []protocol.Package{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) != 6 || p[0] == "" || p[2] == "" {
			return nil, errors.New("incomplete RPM record")
		}
		version := p[2] + "-" + p[3]
		if p[1] != "0" && p[1] != "(none)" && p[1] != "" {
			version = p[1] + ":" + version
		}
		vendor := p[5]
		if vendor == "(none)" {
			vendor = ""
		}
		item := protocol.Package{ID: p[0] + ":" + p[4], Name: p[0], Version: version, Architecture: p[4], Publisher: vendor}
		if distro != "" {
			item.PURL = packagePURL("rpm", distro, p[0], version, p[4], distro+"-"+distributionVersion)
		}
		packages = append(packages, item)
	}
	return packages, nil
}

func parseAPK(text, distro, distributionVersion string) ([]protocol.Package, error) {
	packages := []protocol.Package{}
	for _, stanza := range strings.Split(strings.TrimSpace(text), "\n\n") {
		if strings.TrimSpace(stanza) == "" {
			continue
		}
		values := map[string]string{}
		for _, line := range strings.Split(stanza, "\n") {
			if len(line) > 2 && line[1] == ':' {
				values[line[:1]] = line[2:]
			}
		}
		if values["P"] == "" || values["V"] == "" {
			return nil, fmt.Errorf("incomplete APK record")
		}
		item := protocol.Package{ID: values["P"] + ":" + values["A"], Name: values["P"], Version: values["V"], Architecture: values["A"], Publisher: distro}
		if distro != "" {
			item.PURL = packagePURL("apk", distro, item.Name, item.Version, item.Architecture, distro+"-"+distributionVersion)
		}
		packages = append(packages, item)
	}
	return packages, nil
}
