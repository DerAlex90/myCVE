#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$BinaryPath = (Join-Path $PSScriptRoot 'mycve-agent.exe')
)
$ErrorActionPreference = 'Stop'
$agentConfigSource = (Resolve-Path -LiteralPath $ConfigPath).Path
$agentBinarySource = (Resolve-Path -LiteralPath $BinaryPath).Path
$agentSettings = Get-Content -LiteralPath $agentConfigSource -Raw | ConvertFrom-Json
if (-not $agentSettings.server_url -or -not $agentSettings.agent_id -or -not $agentSettings.token) {
    throw 'Device-specific server configuration is incomplete.'
}
$agentDestination = Join-Path $env:ProgramData 'myCVE-Agent'
$agentInstalledBinary = Join-Path $agentDestination 'mycve-agent.exe'
$agentInstalledConfig = Join-Path $agentDestination 'config.json'
$agentState = Join-Path $agentDestination 'state'
& $agentBinarySource check --config $agentConfigSource
if ($LASTEXITCODE -ne 0) { throw 'Configuration validation failed.' }
$existing = Get-Service -Name myCVEAgent -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') { Stop-Service -InputObject $existing }
    $existing.Dispose()
    & $agentInstalledBinary service uninstall
    if ($LASTEXITCODE -ne 0) { throw 'Existing service could not be removed.' }
}
New-Item -ItemType Directory -Path $agentDestination -Force | Out-Null
& icacls.exe $agentDestination /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Private service directory permissions could not be set.' }
Copy-Item -LiteralPath $agentBinarySource -Destination $agentInstalledBinary -Force
$agentSettings | Add-Member -NotePropertyName state_dir -NotePropertyValue $agentState -Force
$agentJson = $agentSettings | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($agentInstalledConfig, $agentJson, [System.Text.UTF8Encoding]::new($false))
& $agentInstalledBinary service install --config $agentInstalledConfig --state-dir $agentState
if ($LASTEXITCODE -ne 0) { throw 'Windows service installation failed.' }
& $agentInstalledBinary service start
if ($LASTEXITCODE -ne 0) { throw 'Windows service start failed.' }
Write-Host 'myCVE Agent installed. Status: Get-Service myCVEAgent'
Write-Host 'Logs: Windows Application Event Log, source myCVEAgent'
