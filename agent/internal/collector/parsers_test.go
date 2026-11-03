package collector

import (
	"testing"
)

func TestDebianUsesSourceIdentityAndKeepsBinaryVersion(t *testing.T) {
	items, err := parseDPKG("libexample:amd64\t2:1.2-3+b1\tamd64\texample-source\t2:1.2-3\tii \nremoved\t1.0\tall\tremoved\t1.0\trc \n", "debian", "12")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "libexample" || items[0].Version != "2:1.2-3+b1" || items[0].SourceName != "example-source" || items[0].SourceVersion != "2:1.2-3" || items[0].Ecosystem != "Debian:12" {
		t.Fatalf("incorrect binary/source mapping: %+v", items)
	}
	if items[0].PURL != "pkg:deb/debian/example-source@2:1.2-3?arch=amd64&distro=debian-12" {
		t.Fatalf("unexpected purl: %s", items[0].PURL)
	}
	ubuntu, err := parseDPKG("example\t1.0\tall\t\t\tii \n", "ubuntu", "24.04")
	if err != nil || ubuntu[0].Ecosystem != "" {
		t.Fatal("Ubuntu must not be guessed into Debian's vulnerability namespace")
	}
}

func TestIncompletePackageDatabasesCannotBecomeEmptyCompleteInventories(t *testing.T) {
	if _, err := parseDPKG("truncated\t1.0", "debian", "12"); err == nil {
		t.Fatal("expected malformed dpkg error")
	}
	if _, err := parseRPM("openssl\t0\t3.0", "rocky", "9"); err == nil {
		t.Fatal("expected malformed RPM error")
	}
	if _, err := parseAPK("P:openssl\nA:x86_64\n", "alpine", "3.22"); err == nil {
		t.Fatal("expected malformed APK error")
	}
}

func TestRPMEpochReleaseAndAlpineVersion(t *testing.T) {
	items, err := parseRPM("openssl\t1\t3.0.1\t7.el9\tx86_64\tExample Vendor\n", "rocky", "9")
	if err != nil || len(items) != 1 || items[0].Version != "1:3.0.1-7.el9" || items[0].Architecture != "x86_64" {
		t.Fatalf("RPM parse failed: %+v %v", items, err)
	}
	apk, err := parseAPK("P:musl\nV:1.2.5-r10\nA:aarch64\no:musl\n\nP:curl\nV:8.12.1-r1\nA:aarch64\n", "alpine", "3.22")
	if err != nil || len(apk) != 2 || apk[0].Version != "1.2.5-r10" {
		t.Fatalf("APK parse failed: %+v %v", apk, err)
	}
}

func TestWindowsAppxDuplicatesAndCoexistingVersions(t *testing.T) {
	data := []byte(`[{"Name":"Example.App","Version":"1.0","Architecture":"X64","Publisher":"Example"},{"Name":"Example.App","Version":"1.0","Architecture":"X64","Publisher":"Example"},{"Name":"Example.App","Version":"2.0","Architecture":"X64","Publisher":"Example"}]`)
	items := parseWindowsAppx(data)
	if !items.Complete || len(items.Packages) != 2 || items.Packages[0].ID == items.Packages[1].ID {
		t.Fatal("coexisting Appx versions must remain distinguishable")
	}
	if parseWindowsAppx([]byte(`{"Name":"incomplete"}`)).Complete {
		t.Fatal("malformed Appx output must be partial")
	}
}

func TestNestedSBOMAndStableReferences(t *testing.T) {
	input := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"app","bom-ref":"app","version":"1.0","components":[{"name":"library","purl":"pkg:pypi/library@2.0","version":"2.0"}]}]}`)
	first := parseSBOM("sbom:test", input)
	if !first.Complete || len(first.Packages) != 2 {
		t.Fatalf("nested SBOM failed: %+v", first)
	}
	second := parseSBOM("sbom:test", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"app","bom-ref":"app","version":"2.0"}]}`))
	if first.Packages[0].ID != second.Packages[0].ID {
		t.Fatal("bom-ref must survive version changes")
	}
	if parseSBOM("sbom:test", []byte(`{"bomFormat":"SPDX"}`)).Complete {
		t.Fatal("unsupported SBOM must not clear inventory")
	}
	if parseSBOM("sbom:test", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)).Complete {
		t.Fatal("empty SBOM is not an instruction to erase inventory")
	}
}

func TestInvalidSBOMVersionAndConflictingReferencesAreNotAuthoritative(t *testing.T) {
	for _, input := range []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.4|1.5","components":[{"name":"app"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"app","bom-ref":"same","version":"1.0"},{"name":"other","bom-ref":"same","version":"2.0"}]}`,
	} {
		if parseSBOM("sbom:test", []byte(input)).Complete {
			t.Fatal("ambiguous SBOM must not retire prior inventory")
		}
	}
}
