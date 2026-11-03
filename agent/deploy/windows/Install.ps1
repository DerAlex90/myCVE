#Requires -RunAsAdministrator
# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0
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
$agentStage = Join-Path $env:ProgramData ('myCVE-Agent-stage-' + [Guid]::NewGuid().ToString('N'))
$agentServiceBefore = Get-CimInstance Win32_Service -Filter "Name='myCVEAgent'"
$agentWasRunning = $agentServiceBefore -and $agentServiceBefore.State -eq 'Running'
if ($agentServiceBefore -and $agentServiceBefore.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')) {
    throw 'This installer manages LocalSystem services. Review the existing custom service account before upgrading.'
}
$agentChanged = $false
$agentSucceeded = $false
$agentRolledBack = $false
$agentFilesChanged = $false
$agentOldRootAcl = $null
$agentOldBinaryAcl = $null
$agentOldConfigAcl = $null

function Set-PrivateAccess([string]$Path, [bool]$Directory) {
    $acl = if ($Directory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = [System.Security.Principal.SecurityIdentifier]::new($sid)
        $rule = if ($Directory) {
            [System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        } else {
            [System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'Allow')
        }
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-NoLink([string]$Path) {
    if ((Test-Path -LiteralPath $Path) -and ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Installation paths must not be symbolic links or reparse points.'
    }
}
function Assert-AgentExit([string]$Message) {
    if ($LASTEXITCODE -ne 0) { throw $Message }
}
try {
    foreach ($path in @($agentDestination,$agentInstalledBinary,$agentInstalledConfig,$agentState)) { Assert-NoLink $path }
    New-Item -ItemType Directory -Path $agentStage | Out-Null
    Set-PrivateAccess $agentStage $true
    $stagedBinary = Join-Path $agentStage 'mycve-agent.exe'
    $stagedConfig = Join-Path $agentStage 'config.json'
    Copy-Item -LiteralPath $agentBinarySource -Destination $stagedBinary
    $agentSettings | Add-Member -NotePropertyName state_dir -NotePropertyValue $agentState -Force
    [IO.File]::WriteAllText($stagedConfig, ($agentSettings | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    & $stagedBinary check --config $stagedConfig
    Assert-AgentExit 'Staged binary or configuration validation failed; existing service is untouched.'
    # Back up readable files before stopping or changing the existing service.
    if (Test-Path -LiteralPath $agentDestination) {
        $agentOldRootAcl = Get-Acl -LiteralPath $agentDestination
        $probe = Join-Path $agentDestination ('write-probe-' + [Guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($probe, '')
        Remove-Item -LiteralPath $probe
    }
    if (Test-Path -LiteralPath $agentInstalledBinary) {
        $agentOldBinaryAcl = Get-Acl -LiteralPath $agentInstalledBinary
        Copy-Item -LiteralPath $agentInstalledBinary -Destination (Join-Path $agentStage 'previous.exe')
    }
    if (Test-Path -LiteralPath $agentInstalledConfig) {
        $agentOldConfigAcl = Get-Acl -LiteralPath $agentInstalledConfig
        Copy-Item -LiteralPath $agentInstalledConfig -Destination (Join-Path $agentStage 'previous.json')
    }
    $agentChanged = $true
    if ($agentServiceBefore) {
        Stop-Service -Name myCVEAgent
        (Get-Service myCVEAgent).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    New-Item -ItemType Directory -Path $agentDestination -Force | Out-Null
    Set-PrivateAccess $agentDestination $true
    foreach ($path in @($agentInstalledBinary,$agentInstalledConfig)) {
        if (Test-Path -LiteralPath $path) {
            (Get-Item -LiteralPath $path -Force).IsReadOnly = $false
            Set-PrivateAccess $path $false
        }
    }
    # Stage and destination are on the same volume; the service definition is retained.
    Move-Item -LiteralPath $stagedBinary -Destination $agentInstalledBinary -Force
    $agentFilesChanged = $true
    Move-Item -LiteralPath $stagedConfig -Destination $agentInstalledConfig -Force
    Set-PrivateAccess $agentInstalledBinary $false
    Set-PrivateAccess $agentInstalledConfig $false
    New-Item -ItemType Directory -Path $agentState -Force | Out-Null
    Set-PrivateAccess $agentState $true
    foreach ($item in Get-ChildItem -LiteralPath $agentState -Recurse -Force) {
        Assert-NoLink $item.FullName
        Set-PrivateAccess $item.FullName $item.PSIsContainer
    }
    & $agentInstalledBinary check --config $agentInstalledConfig
    Assert-AgentExit 'Installed configuration is not readable.'
    & $agentInstalledBinary service install --config $agentInstalledConfig --state-dir $agentState
    Assert-AgentExit 'Service configuration could not be installed or updated.'
    Start-Service -Name myCVEAgent
    (Get-Service myCVEAgent).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Start-Sleep -Seconds 2
    if ((Get-Service myCVEAgent).Status -ne 'Running') { throw 'Agent stopped after startup.' }
    $agentSucceeded = $true
    Write-Host 'myCVE Agent installed and running. Existing state and device identity are preserved.'
} catch {
    $agentFailure = $_
    if ($agentChanged) {
        try {
            $current = Get-Service myCVEAgent -ErrorAction SilentlyContinue
            if ($current -and $current.Status -ne 'Stopped') { Stop-Service myCVEAgent; $current.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
            if (-not $agentServiceBefore -and $current) {
                & $agentInstalledBinary service uninstall
                Assert-AgentExit 'New service cleanup failed.'
            }
            if ($agentFilesChanged) { foreach ($pair in @(@('previous.exe',$agentInstalledBinary),@('previous.json',$agentInstalledConfig))) {
                $backup = Join-Path $agentStage $pair[0]
                if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $pair[1] -Force }
                elseif (-not $agentServiceBefore -and (Test-Path -LiteralPath $pair[1])) { Remove-Item -LiteralPath $pair[1] -Force }
            } }
            if ($agentOldBinaryAcl) { Set-Acl -LiteralPath $agentInstalledBinary -AclObject $agentOldBinaryAcl }
            if ($agentOldConfigAcl) { Set-Acl -LiteralPath $agentInstalledConfig -AclObject $agentOldConfigAcl }
            if ($agentOldRootAcl) { Set-Acl -LiteralPath $agentDestination -AclObject $agentOldRootAcl }
            if ($agentServiceBefore) {
                $restored = Invoke-CimMethod -InputObject $agentServiceBefore -MethodName Change -Arguments @{PathName=$agentServiceBefore.PathName}
                if ($restored.ReturnValue -ne 0) { throw 'Original service path could not be restored.' }
                if ($agentWasRunning) { Start-Service myCVEAgent; (Get-Service myCVEAgent).WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) }
            }
            Write-Warning 'Upgrade failed; previous files and service state restored.'
            $agentRolledBack = $true
        } catch {
            Write-Warning 'Automatic rollback could not finish. Keep the private staging directory for recovery.'
            throw
        }
    }
    throw $agentFailure
} finally {
    # Keep protected recovery files if rollback itself failed.
    if ($agentSucceeded -or $agentRolledBack -or -not $agentChanged) {
        Remove-Item -LiteralPath $agentStage -Recurse -Force -ErrorAction SilentlyContinue
    }
}
