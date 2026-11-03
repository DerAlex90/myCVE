package collector

import "testing"

func TestWindowsVersionMetadataDoesNotExecuteOrAcceptNetworkPaths(t *testing.T) {
	for _, unsafe := range []string{`\\server\share\app.exe`, `app.exe --flag`, `C:\App\app.exe --flag`, `C:\App\app.exe,0 & evil`, `https://example.com/app.exe`} {
		if iconBinaryPath(unsafe) != "" {
			t.Fatalf("accepted unsafe binary path %q", unsafe)
		}
	}
	if iconBinaryPath(`"C:\Program Files\Example\app.exe",0`) != `C:\Program Files\Example\app.exe` {
		t.Fatal("valid icon path not parsed")
	}
	if msiVersion(0x01020304) != "1.2.772" || msiVersion(0) != "" {
		t.Fatal("packed MSI version was misinterpreted")
	}
}

func TestBinaryVersionRequiresSameProductAndManufacturer(t *testing.T) {
	if !sameMetadataProduct("Mozilla Firefox 128.0 (x64 de)", "Mozilla", "Firefox", "Mozilla Corporation") {
		t.Fatal("matching product metadata rejected")
	}
	for _, example := range [][4]string{
		{"Firefox", "Mozilla", "Updater", "Mozilla Corporation"},
		{"Firefox", "Mozilla", "Firefox", "Other Company"},
		{"Office 2021", "Microsoft", "Office 2019", "Microsoft"},
	} {
		if sameMetadataProduct(example[0], example[1], example[2], example[3]) {
			t.Fatal("unrelated executable or edition accepted")
		}
	}
}
