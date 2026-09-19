#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Undo everything install.ps1 did.

.PARAMETER Interface
    Adapter to remove the 802.1X profile from. Auto-detected when omitted.

.PARAMETER RestoreVendorSupplicant
    Re-enable and start the Ruijie supplicant service.

.PARAMETER RestoreNpcap
    Set the Npcap service back to Automatic and start it.
#>
[CmdletBinding()]
param(
    [string]$Interface,
    [switch]$RestoreVendorSupplicant,
    [switch]$RestoreNpcap
)

$ErrorActionPreference = 'Continue'
try { Start-Transcript -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'uninstall.log') -Force | Out-Null } catch {}
$authorId = 49374
$dataDir = 'C:\ProgramData\RJNMSL'
$sysDll = 'C:\Windows\System32\eapmd5.dll'

function Info($m) { Write-Host "[+] $m" }

if (-not $Interface) {
    $Interface = (Get-NetAdapter |
        Where-Object {
            $_.Status -eq 'Up' -and
            $_.MediaType -eq '802.3' -and
            $_.PhysicalMediaType -eq '802.3' -and
            $_.InterfaceDescription -notmatch 'Virtual|VMware|VirtualBox|TAP|VPN|Wi-?Fi|Wireless|Bluetooth|Loopback|WAN Miniport'
        } | Select-Object -First 1).Name
}

if ($Interface) {
    Info "removing 802.1X profile from $Interface"
    Start-Service dot3svc -ErrorAction SilentlyContinue
    netsh lan delete profile interface="$Interface" | Out-Null
    Stop-Service dot3svc -Force -ErrorAction SilentlyContinue
    Set-Service dot3svc -StartupType Manual -ErrorAction SilentlyContinue
}

Info "removing EapHost registration"
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\EapHost\Methods\$authorId" -Recurse -Force -ErrorAction SilentlyContinue

Info "removing DLL and data"
Remove-Item $sysDll -Force -ErrorAction SilentlyContinue
Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue

if ($RestoreVendorSupplicant) {
    Info "re-enabling vendor supplicant"
    Set-Service RJSuService -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service RJSuService -ErrorAction SilentlyContinue
}

if ($RestoreNpcap) {
    Info "restoring Npcap"
    Set-Service npcap -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service npcap -ErrorAction SilentlyContinue
}

Info 'done.'
try { Stop-Transcript | Out-Null } catch {}