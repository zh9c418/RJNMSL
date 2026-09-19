#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install RJNMSL's EAP-MD5 EapHost method and switch the wired NIC to native
    802.1X (no packet-capture driver, no vendor supplicant).

.DESCRIPTION
    * disables the vendor supplicant FIRST (avoid two supplicants fighting)
    * copies eapmd5.dll into System32 and registers it with EapHost
    * sets Wired AutoConfig (dot3svc) to Automatic
    * installs the LAN 802.1X profile and stores the credentials
    * writes the credential file the method reads
    * optionally stops Npcap
    * reconnects and waits for authentication, then renews DHCP

.PARAMETER Interface
    Adapter name/alias to authenticate on. Auto-detected when omitted.

.PARAMETER Username / Password
    Credentials. When omitted they are read from `credentials.txt` in the repo
    root, or prompted for.

.PARAMETER KeepVendorSupplicant
    Do not stop/disable the Ruijie supplicant service.

.PARAMETER KeepNpcap
    Do not stop Npcap (keep it if you still use Wireshark etc.).

.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -Interface "Ethernet" -Username alice -Password 'secret'
#>
[CmdletBinding()]
param(
    [string]$Interface,
    [string]$Username,
    [string]$Password,
    [string]$DllPath,
    [switch]$KeepVendorSupplicant,
    [switch]$KeepNpcap
)

$ErrorActionPreference = 'Stop'
$script:logFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'install.log'
try { Start-Transcript -Path $script:logFile -Force | Out-Null } catch {}
$root = Split-Path -Parent $PSScriptRoot
$dataDir = 'C:\ProgramData\RJNMSL'
$iniPath = Join-Path $dataDir 'eapmd5.ini'
$sysDll = 'C:\Windows\System32\eapmd5.dll'
$authorId = 49374          # 0xC0DE - our EAP method author id
$friendlyName = 'EAP-MD5 (RJNMSL)'

function Info($m) { Write-Host "[+] $m" }

if (-not $DllPath) { $DllPath = Join-Path $root 'target\release\eapmd5.dll' }
if (-not (Test-Path $DllPath)) {
    throw "eapmd5.dll not found at $DllPath - run: cargo build --release --workspace"
}

# --- credentials ---------------------------------------------------------
if (-not $Username -or -not $Password) {
    $credFile = Join-Path $root 'credentials.txt'
    if (Test-Path $credFile) {
        foreach ($line in Get-Content $credFile) {
            if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
            $k, $v = $line.Split('=', 2)
            switch ($k.Trim().ToLower()) {
                'username' { if (-not $Username) { $Username = $v.Trim() } }
                'password' { if (-not $Password) { $Password = $v.Trim() } }
            }
        }
    }
}
if (-not $Username) { $Username = Read-Host '802.1X username' }
if (-not $Password) { $Password = Read-Host '802.1X password' -AsSecureString | ConvertFrom-SecureString -AsPlainText }

# --- interface (physical wired Ethernet that is up) ----------------------
if (-not $Interface) {
    $Interface = (Get-NetAdapter |
        Where-Object {
            $_.Status -eq 'Up' -and
            $_.MediaType -eq '802.3' -and
            $_.PhysicalMediaType -eq '802.3' -and
            $_.InterfaceDescription -notmatch 'Virtual|VMware|VirtualBox|TAP|VPN|Wi-?Fi|Wireless|Bluetooth|Loopback|WAN Miniport'
        } | Select-Object -First 1).Name
}
if (-not $Interface) { throw 'Could not auto-detect a wired adapter; pass -Interface "<name>"' }
Info "adapter      : $Interface"

# --- 1. install DLL + register with EapHost -------------------------------
Info "copying DLL -> $sysDll"
Copy-Item $DllPath $sysDll -Force

$key = "HKLM:\SYSTEM\CurrentControlSet\Services\EapHost\Methods\$authorId\4"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name PeerDllPath              -PropertyType ExpandString -Value $sysDll      -Force | Out-Null
New-ItemProperty -Path $key -Name PeerFriendlyName         -PropertyType String       -Value $friendlyName -Force | Out-Null
New-ItemProperty -Path $key -Name PeerInvokeUsernameDialog -PropertyType DWord        -Value 0            -Force | Out-Null
New-ItemProperty -Path $key -Name PeerInvokePasswordDialog -PropertyType DWord        -Value 0            -Force | Out-Null
New-ItemProperty -Path $key -Name Properties               -PropertyType DWord        -Value 0x173cf8bf   -Force | Out-Null
Info "registered  : $key"

# --- 2. credential file the method reads ---------------------------------
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
if (Test-Path $iniPath) {
    # a previous install locked it down; re-grant write so we can update it
    & icacls $iniPath /inheritance:r /grant:r 'Administrators:(F)' 'SYSTEM:(R)' | Out-Null
    Remove-Item $iniPath -Force -ErrorAction SilentlyContinue
}
@(
    '# RJNMSL EAP-MD5 credentials (read by eapmd5.dll)',
    "username=$Username",
    "password=$Password"
) | Set-Content -Path $iniPath -Encoding ASCII
# the method runs as SYSTEM (needs read); admins can update; nobody else
& icacls $iniPath /inheritance:r /grant:r 'SYSTEM:(R)' 'Administrators:(F)' | Out-Null
Info "credentials  : $iniPath (ACL: SYSTEM:R, Administrators:F)"

# --- 3. stop the vendor supplicant FIRST ---------------------------------
if (-not $KeepVendorSupplicant) {
    foreach ($svc in @('RJSuService')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Info "stopping/disabling $svc"
            Get-Process -Name 'RuijieSupplicant', '8021x', 'suservice', 'SoftwareManager' -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
            Stop-Service $svc -Force -ErrorAction SilentlyContinue
            Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
}

# --- 4. optionally stop Npcap (no longer needed) -------------------------
if (-not $KeepNpcap) {
    $n = Get-Service -Name 'npcap' -ErrorAction SilentlyContinue
    if ($n) {
        Info 'stopping Npcap'
        Stop-Service npcap -Force -ErrorAction SilentlyContinue
        Set-Service npcap -StartupType Manual -ErrorAction SilentlyContinue
    }
}

# --- 5. dot3svc + profile ------------------------------------------------
Info 'setting dot3svc to Automatic'
Set-Service dot3svc -StartupType Automatic
Start-Service dot3svc
Info ("dot3svc      : " + (Get-Service dot3svc).Status)

$profileXml = Join-Path $root 'crates\eapmd5\eap-md5.xml'
if (-not (Test-Path $profileXml)) { throw "missing profile XML: $profileXml" }

# credentials XML is only used so OneX reports "Credentials Configured: Yes";
# the method itself ignores the blob and reads $iniPath.
$credsXml = Join-Path $env:TEMP 'rjnmsl-creds.xml'
@"
<?xml version="1.0"?>
<EapHostUserCredentials xmlns="http://www.microsoft.com/provisioning/EapHostUserCredentials" xmlns:eapCommon="http://www.microsoft.com/provisioning/EapCommon" xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
  <EapMethod>
    <eapCommon:Type>4</eapCommon:Type>
    <eapCommon:AuthorId>$authorId</eapCommon:AuthorId>
  </EapMethod>
  <Credentials>
    <baseEap:Eap>
      <baseEap:Type>4</baseEap:Type>
      <baseEap:EapType>
        <baseEap:Username>$Username</baseEap:Username>
        <baseEap:Password>$Password</baseEap:Password>
      </baseEap:EapType>
    </baseEap:Eap>
  </Credentials>
</EapHostUserCredentials>
"@ | Set-Content -Path $credsXml -Encoding UTF8

Info 'installing 802.1X profile'
netsh lan add profile filename="$profileXml" interface="$Interface" | Out-Null
netsh lan set autoconfig enabled=yes interface="$Interface" | Out-Null
netsh lan set eapuserdata filename="$credsXml" allusers=yes interface="$Interface" | Out-Null
Remove-Item $credsXml -Force -ErrorAction SilentlyContinue

# --- 6. reconnect, wait for authentication, renew DHCP -------------------
Info 'reconnecting...'
netsh lan reconnect interface="$Interface" | Out-Null
Start-Sleep -Seconds 12
netsh lan show interfaces
ipconfig /renew "$Interface" | Out-Null
Start-Sleep -Seconds 3

Info 'status:'
netsh lan show interfaces
netsh lan show profiles interface="$Interface"

Write-Host ''
Write-Host 'Check connectivity with:  ping <your gateway>'
Write-Host "Method log:               $dataDir\eapmd5.log"
try { Stop-Transcript | Out-Null } catch {}