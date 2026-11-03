//go:build windows

package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestWindowsRegistryVersionFallback(t *testing.T) {
	name := `Software\myCVE-Version-Test-` + filepath.Base(t.TempDir())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, name, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, name)
	defer key.Close()
	budget := 10
	key.SetStringValue("QuietDisplayVersion", "2.3.4")
	version, source := registryVersion(context.Background(), key, "Example", "Example", &budget)
	if version != "2.3.4" || source != "registry.QuietDisplayVersion" {
		t.Fatal("alternative version metadata ignored")
	}
	key.DeleteValue("QuietDisplayVersion")
	key.SetDWordValue("WindowsInstaller", 1)
	key.SetDWordValue("Version", 0x01020304)
	version, source = registryVersion(context.Background(), key, "Example", "Example", &budget)
	if version != "1.2.772" || source != "registry.MSI.Version" {
		t.Fatal("MSI version not decoded")
	}
}

func TestWindowsReadsProductVersionWithoutExecutingBinary(t *testing.T) {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll")
	version, product, company := fileProductMetadata(path)
	if version == "" || product == "" || company == "" {
		t.Fatal("native version-resource API returned incomplete metadata")
	}
}
