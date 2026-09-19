#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install RJNMSL's EAP-MD5 EapHost method and switch the wired NIC to native
    802.1X (no packet-capture driver, no vendor supplicant).

.DESCRIPTION
    * copies eapmd5.dll into System32 and registers it with EapHost
    * sets Wired AutoConfig (dot3svc) to Automatic
    * installs the LAN 802.1X profile and stores the credentials
    * writes the credential file the method reads
    * optionally disables the Ruijie supplicant service
    * optionally stops Npcap

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
$root = Split-Path -Parent $PSScriptRoot
$dataDir = 'C:\ProgramData\RJNMSL'
$iniPath = Join-Path $dataDir 'eapmd5.ini'
$sysDll = 'C:\Windows\System32\eapmd5.dll'
$authorId = 49374          # 0xC0DE - our EAP method author id
$friendlyName = 'EAP-MD5 (RJNMSL)'

function Info($m) { Write-Host "[+] $m" }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

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

# --- interface -----------------------------------------------------------
if (-not $Interface) {
    $Interface = (Get-NetAdapter |
        Where-Object {
            $_.Status -eq 'Up' -and
            $_.InterfaceDescription -notmatch 'Virtual|TAP|VPN|Wi-?Fi|Wireless|Bluetooth|Loopback|WAN Miniport'
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
@(
    '# RJNMSL EAP-MD5 credentials (read by eapmd5.dll)',
    "username=$Username",
    "password=$Password"
) | Set-Content -Path $iniPath -Encoding ASCII
# lock the file down to Administrators + SYSTEM
& icacls $iniPath /inheritance:r /grant:r 'SYSTEM:(R)' 'Administrators:(R)' | Out-Null
Info "credentials  : $iniPath (ACL restricted)"

# --- 3. dot3svc = Automatic ----------------------------------------------
Info 'setting dot3svc to Automatic'
Set-Service dot3svc -StartupType Automatic
Start-Service dot3svc
Info ("dot3svc      : " + (Get-Service dot3svc).Status)

# --- 4. LAN profile + eapuserdata ----------------------------------------
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
netsh lan show profiles interface="$Interface"

# --- 5. optionally stop the vendor supplicant ----------------------------
if (-not $KeepVendorSupplicant) {
    foreach ($svc in @('RJSuService')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Info "stopping/disabling $svc"
            Get-Process -Name 'RuijieSupplicant', '8021x', 'suservice' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Stop-Service $svc -Force -ErrorAction SilentlyContinue
            Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
}

# --- 6. optionally stop Npcap (no longer needed) -------------------------
if (-not $KeepNpcap) {
    $n = Get-Service -Name 'npcap' -ErrorAction SilentlyContinue
    if ($n) {
        Info 'stopping Npcap'
        Stop-Service npcap -Force -ErrorAction SilentlyContinue
        Set-Service npcap -StartupType Manual -ErrorAction SilentlyContinue
    }
}

Info 'done. reconnecting...'
netsh lan reconnect interface="$Interface" | Out-Null
Write-Host ''
Write-Host 'Check status with:  netsh lan show interfaces'
Write-Host "Method log:         $dataDir\eapmd5.log"