// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

package collector

import (
	"fmt"
	"regexp"
	"strings"
)

var localWindowsBinary = regexp.MustCompile(`(?i)^[a-z]:\\[^\x00\r\n]*\.(exe|dll)$`)
var iconIndex = regexp.MustCompile(`,\s*-?\d+\s*$`)
var productDecorations = regexp.MustCompile(`(?i)\((x64|x86|amd64|arm64|32[ -]bit|64[ -]bit)(\s+[a-z]{2}(-[a-z]{2})?)?\)`)
var numericVersion = regexp.MustCompile(`\b\d+(\.\d+)+\b`)
var identityWords = regexp.MustCompile(`[^a-z0-9]+`)

func iconBinaryPath(value string) string {
	value = strings.TrimSpace(iconIndex.ReplaceAllString(value, ""))
	value = strings.Trim(value, `"`)
	if !localWindowsBinary.MatchString(value) {
		return ""
	}
	return value
}

func msiVersion(value uint64) string {
	if value == 0 || value > 0xffffffff {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", value>>24, (value>>16)&255, value&65535)
}

func metadataVendor(value string) string {
	parts := strings.Fields(identityWords.ReplaceAllString(strings.ToLower(value), " "))
	legal := map[string]bool{"inc": true, "incorporated": true, "corporation": true, "corp": true, "llc": true, "ltd": true, "limited": true, "gmbh": true}
	kept := []string{}
	for _, part := range parts {
		if !legal[part] {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " ")
}

func metadataProduct(value, vendor string) string {
	value = productDecorations.ReplaceAllString(value, " ")
	value = numericVersion.ReplaceAllString(value, " ")
	value = strings.TrimSpace(identityWords.ReplaceAllString(strings.ToLower(value), " "))
	return strings.TrimSpace(strings.TrimPrefix(value, metadataVendor(vendor)+" "))
}

func sameMetadataProduct(display, publisher, product, company string) bool {
	manufacturer, name := metadataVendor(publisher), metadataProduct(display, publisher)
	return manufacturer != "" && name != "" && metadataVendor(publisher) == metadataVendor(company) && name == metadataProduct(product, company)
}
