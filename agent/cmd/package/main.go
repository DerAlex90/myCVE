// Copyright (c) 2026 Alexander Speka (DerAlex90)
// SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

// Command package creates reproducible client bundles; it is not part of the agent service.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type entry struct {
	name, path string
	mode       int64
}

func main() {
	if err := build(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build() error {
	output := flag.String("out", "../dist/agent", "release output directory")
	flag.Parse()
	if err := os.MkdirAll(*output, 0755); err != nil {
		return err
	}
	var checksums []string
	for _, target := range []struct{ os, arch string }{{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}} {
		name := "mycve-agent"
		if target.os == "windows" {
			name += ".exe"
		}
		dir := filepath.Join(*output, "bin", target.os+"-"+target.arch)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		binary := filepath.Join(dir, name)
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", binary, "./cmd/mycve-agent")
		cmd.Env = append(os.Environ(), "GOOS="+target.os, "GOARCH="+target.arch, "CGO_ENABLED=0")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		files := []entry{{name, binary, 0755}, {"README.md", "README.md", 0644}, {"LICENSE", "../LICENSE", 0644}, {"NOTICE", "../NOTICE", 0644}, {"THIRD_PARTY_NOTICES.txt", "THIRD_PARTY_NOTICES.txt", 0644}, {"config.example.json", "config.example.json", 0600}}
		archiveName := "mycve-agent-" + target.os + "-" + target.arch
		if target.os == "linux" {
			files = append(files, entry{"install.sh", "deploy/linux/install.sh", 0755}, entry{"mycve-agent.service", "deploy/linux/mycve-agent.service", 0644})
			archiveName += ".tar.gz"
		} else {
			files = append(files, entry{"Install.ps1", "deploy/windows/Install.ps1", 0644}, entry{"Uninstall.ps1", "deploy/windows/Uninstall.ps1", 0644})
			archiveName += ".zip"
		}
		path := filepath.Join(*output, archiveName)
		if err := archive(path, files, target.os == "windows"); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checksums = append(checksums, fmt.Sprintf("%x  %s\n", sha256.Sum256(data), archiveName))
		fmt.Println("Created", archiveName)
	}
	sort.Strings(checksums)
	return os.WriteFile(filepath.Join(*output, "SHA256SUMS"), []byte(strings.Join(checksums, "")), 0644)
}

func archive(path string, files []entry, windows bool) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	if windows {
		writer := zip.NewWriter(file)
		for _, item := range files {
			data, err := os.ReadFile(item.path)
			if err != nil {
				writer.Close()
				return err
			}
			header := &zip.FileHeader{Name: "mycve-agent/" + item.name, Method: zip.Deflate, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
			header.SetMode(os.FileMode(item.mode))
			entry, err := writer.CreateHeader(header)
			if err != nil {
				writer.Close()
				return err
			}
			if _, err := entry.Write(data); err != nil {
				writer.Close()
				return err
			}
		}
		return writer.Close()
	}
	compressed := gzip.NewWriter(file)
	writer := tar.NewWriter(compressed)
	for _, item := range files {
		info, err := os.Stat(item.path)
		if err != nil {
			writer.Close()
			compressed.Close()
			return err
		}
		header := &tar.Header{Name: "mycve-agent/" + item.name, Mode: item.mode, Size: info.Size(), Typeflag: tar.TypeReg}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		input, err := os.Open(item.path)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, input)
		input.Close()
		if err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return compressed.Close()
}
