# myCVE inventory agent

Copyright (c) 2026 **Alexander Speka (DerAlex90)**. From 0.4.0, the project's own code uses the **myCVE Attribution License 1.0**. Use, including commercial use, is free under its attribution requirements. Keep LICENSE, NOTICE and all required third-party notices. Removing the project's own attribution requires a prior separate paid written agreement. Earlier MIT releases retain their existing rights. Run `mycve-agent license` to display the attribution and license reference; the complete governing text is included in LICENSE.

A small Go data sender for Linux and Windows. It reports system information and installed packages to the self-hosted myCVE server. The server stores inventory, changes and collector errors and schedules vulnerability checks. No desktop UI or Python installation is needed on monitored devices.

## Register a device

1. In myCVE create an asset under **Systeme & Inventar**.
2. Open **Inventar-Agenten**, register that asset and download its one-time configuration.
3. Download the agent package for the device's OS and architecture. Verify the package against the server's `SHA256SUMS` using a trusted connection.
4. Extract the package and place the configuration on that device. Each device needs its own registration and state directory.

The device token can submit inventory only for its assigned asset. The workspace administrator key must not be placed on agents. Server URLs must use HTTPS. For explicit local tests only, `allow_insecure_localhost: true` permits HTTP to localhost/127.0.0.1/::1. TLS certificate validation cannot be disabled; optional `ca_file` adds a trusted organization CA.

Reports are limited to 10 MB and 10,000 packages. The server accepts at most ten new reports per device per minute by default; unchanged replay IDs are exempt. Package data is sent to the configured myCVE server. Only that server performs external CVE/OSV lookups.

## Test without installation

```sh
./mycve-agent check --config /path/to/mycve-agent-config.json
./mycve-agent collect --config /path/to/mycve-agent-config.json
./mycve-agent once --config /path/to/mycve-agent-config.json
```

On Windows use `mycve-agent.exe`. `collect` prints inventory and sends nothing. `once` sends one current snapshot and retries a previously persisted unacknowledged snapshot first. The configuration and state directory must be writable/protected for the account running the agent. Do not publish inventory output or device configuration in public issues.

## Linux service

Initial targets: Linux amd64/arm64 with dpkg, RPM or APK. The included installer uses systemd:

```sh
sudo ./install.sh /path/to/mycve-agent-config.json
systemctl status mycve-agent.service
journalctl -u mycve-agent.service
```

The installer creates an unprivileged `mycve-agent` account, installs the executable under `/usr/local/lib/mycve-agent`, configuration under `/etc/mycve-agent`, and persistent state under `/var/lib/mycve-agent`. Upgrades keep the device identity. The service uses filesystem restrictions; configured SBOMs must be accessible to this account and outside protected home directories. Other Linux supervisors can invoke `mycve-agent run --config ... --state-dir ...` directly. This release does not claim native package collection on every Unix variant.

To remove the Linux service while retaining configuration and identity:

```sh
sudo systemctl disable --now mycve-agent.service
sudo rm /etc/systemd/system/mycve-agent.service
sudo systemctl daemon-reload
```

## Windows service

Initial targets: Windows amd64/arm64 supported by Go 1.27. Run the bundled installer from an elevated PowerShell terminal:

```powershell
.\Install.ps1 -ConfigPath C:\Path\mycve-agent-config.json
Get-Service myCVEAgent
```

The service uses the native Windows Service Control Manager, starts automatically, and restarts on process failures. Configuration, executable and state live under `%ProgramData%\myCVE-Agent`, restricted to Administrators and SYSTEM. Runtime messages use the Windows Application Event Log, source `myCVEAgent`. `Uninstall.ps1` removes the service and retains local identity/configuration. PowerShell execution policy and organizational signing rules still apply; this source release does not claim Authenticode signing.

From 0.5, upgrades validate a private staged binary and configuration and back up the old files before stopping the service. The existing service definition is updated in place. A failed replacement restores the previous files, service path and running state; if recovery itself fails, the private staging directory is retained for recovery. Device state is kept. Custom service accounts are rejected before any service change, since their file-access policy needs individual review. The Windows CI exercises actual installation, upgrade, configuration ACLs and rollback after an intentionally failing replacement.

The Windows collector reads machine-wide 32/64-bit application registry entries, currently loaded user hives, Appx packages and Windows build information. It does not query `Win32_Product`, repair software or execute commands received from the server. Offline user hives and portable applications are not guaranteed to be discovered. Unavailable or restricted collectors are reported as incomplete.

## Configuration

The server download is ready to use. Optional settings:

```json
{
  "server_url": "https://mycve.example.com",
  "agent_id": "the-server-issued-agent-id",
  "token": "mycve_agent_REPLACE_WITH_DEVICE_TOKEN_FROM_SERVER",
  "interval_seconds": 21600,
  "allow_insecure_localhost": false,
  "ca_file": "/etc/mycve-agent/company-ca.pem",
  "state_dir": "/var/lib/mycve-agent",
  "sbom_paths": ["/var/lib/mycve-agent/sbom/service.cdx.json"]
}
```

Paths are relative to the configuration's directory unless absolute. The interval is 300–604800 seconds, default six hours, with a small device-specific jitter. Failed transfers retry with bounded backoff. The single pending report is persisted atomically with private file permissions and retained until the server acknowledges the same report ID. A new current inventory is collected after recovery. Process locks prevent two instances from using the same state directory.

SBOMs support CycloneDX JSON 1.4–1.7 and are read only from explicitly configured files. Package-manager inventory does not discover every project's Python/npm/etc. dependencies automatically.

## Matching accuracy

After registration and service installation, collection, reporting, product identification and vulnerability scans run automatically. Server 0.3 also processes existing inventories from agent 0.2. Upgrade the server before deploying agent 0.3, which adds optional version-provenance metadata.

Agent 0.5 adds optional Linux package-role and exact installed-kernel-release metadata. The existing host kernel field remains the reported running release. Update the server before installing the new agent. The server can also derive conservative kernel/header context from existing 0.2–0.4 reports; exact release evidence is required to identify a running image. A missing match is not proof that a custom kernel or backport is safe.

Debian, Ubuntu and Alpine use source-package identities and their actual distribution releases. AlmaLinux, Rocky Linux and RHEL use their own OSV namespaces. Other distribution packages remain explicitly unresolved when an authoritative advisory namespace is unavailable; patched distribution versions are not reinterpreted as unpatched upstream releases.

Windows applications are automatically identified by the server against the official NVD CPE dictionary, requiring a matching manufacturer and product. If DisplayVersion is absent, the agent tries alternative registry strings, the packed MSI version and matching local executable ProductVersion metadata. Local executables are read, never launched. Resource lookups are bounded and restricted to fixed local drives without reparse points. Loaded user hives use registry values only. Network/command icon paths and metadata from unrelated products or vendors are rejected. The reported version source is retained for inspection.

The server retries failed or ambiguous identification automatically, and displays coverage and evidence. Missing versions or absent catalog entries remain unknown rather than requiring manual product-ID maintenance or implying an all-clear. Reported Windows OS metadata is not a full Windows patch-compliance assessment.

Complete reports may retire missing packages only within their own collector. Failed or missing collectors retain their prior inventory. Manual SBOM imports have a separate origin. Replay IDs are idempotent, older reports cannot overwrite newer snapshots, and another device ID cannot reuse a bound key. Token rotation supports explicit device-binding reset after a reinstall.

## Build and test

Requires Go 1.26+ (release builds use Go 1.27) and a standard C toolchain only for race-enabled tests. Dependencies are pinned in `go.mod` / `go.sum`.

```sh
go test ./...
go vet ./...
go run ./cmd/package --out ../dist/agent
```

The packager cross-compiles Linux and Windows for amd64/arm64 with CGO disabled, includes service installers and documentation, and emits `SHA256SUMS`. Linux and Windows-native tests are defined in the repository's CI. A Windows service runtime test requires an actual elevated Windows environment; cross-compilation alone does not prove service installation there.
