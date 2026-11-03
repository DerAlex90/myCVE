//go:build windows

package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func localMetadataPath(path string) bool {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(path) {
		return false
	}
	root := volume + `\`
	wide, err := windows.UTF16PtrFromString(root)
	if err != nil || windows.GetDriveType(wide) != windows.DRIVE_FIXED {
		return false
	}
	// Walk from the volume root, refusing junctions before accessing their children.
	current := root
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), root), `\`) {
		current = filepath.Join(current, part)
		wide, err = windows.UTF16PtrFromString(current)
		if err != nil {
			return false
		}
		attributes, err := windows.GetFileAttributes(wide)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return false
		}
	}
	return true
}

func fileProductMetadata(path string) (version, product, company string) {
	path = filepath.Clean(path)
	if !localWindowsBinary.MatchString(path) || !localMetadataPath(path) {
		return "", "", ""
	}
	var handle windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &handle)
	if err != nil || size == 0 || size > 1_000_000 {
		return "", "", ""
	}
	buffer := make([]byte, size)
	if windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buffer[0])) != nil {
		return "", "", ""
	}
	var translation *uint16
	var length uint32
	if windows.VerQueryValue(unsafe.Pointer(&buffer[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&translation), &length) != nil || length < 4 {
		return "", "", ""
	}
	ids := unsafe.Slice(translation, 2)
	query := func(name string) string {
		var text *uint16
		var count uint32
		key := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, ids[0], ids[1], name)
		if windows.VerQueryValue(unsafe.Pointer(&buffer[0]), key, unsafe.Pointer(&text), &count) != nil || count == 0 || count > 2000 {
			return ""
		}
		return strings.TrimSpace(windows.UTF16ToString(unsafe.Slice(text, int(count))))
	}
	return query("ProductVersion"), query("ProductName"), query("CompanyName")
}

func registryVersion(ctx context.Context, key registry.Key, display, publisher string, budget *int) (string, string) {
	for _, name := range []string{"DisplayVersion", "QuietDisplayVersion", "Version"} {
		if version := value(key, name); version != "" {
			return version, "registry." + name
		}
	}
	installer, _, _ := key.GetIntegerValue("WindowsInstaller")
	if installer == 1 {
		packed, _, _ := key.GetIntegerValue("Version")
		if version := msiVersion(packed); version != "" {
			return version, "registry.MSI.Version"
		}
	}
	if *budget <= 0 {
		return "", ""
	}
	paths := []string{}
	if path := iconBinaryPath(value(key, "DisplayIcon")); path != "" {
		paths = append(paths, path)
	}
	directory := strings.Trim(value(key, "InstallLocation"), `"`)
	if len(directory) > 3 && directory[1] == ':' && directory[2] == '\\' {
		for _, location := range []string{directory, filepath.Join(directory, "bin")} {
			if !localMetadataPath(location) {
				continue
			}
			folder, err := os.Open(location)
			if err != nil {
				continue
			}
			entries, _ := folder.ReadDir(64)
			folder.Close()
			for _, entry := range entries {
				if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".exe") {
					paths = append(paths, filepath.Join(location, entry.Name()))
				}
			}
		}
	}
	for _, path := range paths {
		if ctx.Err() != nil || *budget <= 0 {
			break
		}
		*budget--
		version, product, company := fileProductMetadata(path)
		if version != "" && sameMetadataProduct(display, publisher, product, company) {
			return version, "file.ProductVersion"
		}
	}
	return "", ""
}
