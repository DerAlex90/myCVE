#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$agentBinary = Join-Path $env:ProgramData 'myCVE-Agent\mycve-agent.exe'
& $agentBinary service stop
if ($LASTEXITCODE -ne 0) { throw 'Service could not be stopped.' }
& $agentBinary service uninstall
if ($LASTEXITCODE -ne 0) { throw 'Service could not be uninstalled.' }
Write-Host 'Service removed. Configuration and state were retained for a later reinstall.'
