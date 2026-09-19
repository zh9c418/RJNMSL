<#
.SYNOPSIS
    Generate wpcap.lib / Packet.lib import libraries from the installed Npcap
    DLLs, so the rj8021x crate can link without downloading the Npcap SDK.

.DESCRIPTION
    Npcap's runtime installer ships wpcap.dll / Packet.dll but not the import
    libraries. This script exports the symbol tables with `dumpbin /exports`
    and creates the import libs with `lib /def`.

    Requires dumpbin.exe and lib.exe on PATH (run from a "x64 Native Tools
    Command Prompt for VS", or install the MSVC build tools).
#>
[CmdletBinding()]
param(
    [string]$NpcapDir = "$env:SystemRoot\System32\Npcap",
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'crates\rj8021x\.npcap')
)

$ErrorActionPreference = 'Stop'

foreach ($tool in 'dumpbin.exe', 'lib.exe') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool not found on PATH. Run this from an 'x64 Native Tools Command Prompt for VS'."
    }
}
if (-not (Test-Path $NpcapDir)) { throw "Npcap runtime dir not found: $NpcapDir (is Npcap installed?)" }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

foreach ($name in 'wpcap', 'Packet') {
    $dll = Join-Path $NpcapDir "$name.dll"
    if (-not (Test-Path $dll)) { throw "missing $dll" }

    $def = Join-Path $OutDir "$name.def"
    $lib = Join-Path $OutDir "$name.lib"

    $names = & dumpbin /exports $dll |
        ForEach-Object {
            if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+([A-Za-z_]\S*)\s*$') { $Matches[1] }
        }
    if (-not $names) { throw "no exports parsed from $dll" }

    @("LIBRARY $name", 'EXPORTS') + $names | Set-Content -Path $def -Encoding ASCII
    & lib /nologo /def:"$def" /machine:x64 /out:"$lib" | Out-Null

    Write-Host ("[+] {0} -> {1} ({2} exports)" -f $name, $lib, $names.Count)
}
Write-Host '[+] done. `cargo build -p rj8021x` should now link.'