# RJNMSL

[简体中文](README.md) | English

> **This is a vibecoding project.** The code is predominantly AI-generated, mainly
> by **deepseek-v4.1-flash** and **gpt-5.6-sol**. A human supplied the requirements,
> captured packets, read the logs and made minor fixes. Review it before relying on it.

**A lightweight replacement for the Ruijie campus-network supplicant on Windows.**

RJNMSL authenticates a wired 802.1X port without installing a vendor kernel
driver, without a SYSTEM "auth broker" service, and — in the recommended
configuration — **without any packet-capture driver at all**.

---

## Background

Many Chinese campus networks hand out a proprietary client (Ruijie Supplicant,
`SuService.exe` / `8021x.exe`) to log in to 802.1X. That client:

* installs a kernel-mode NDIS packet driver (PCAUSA `PCASp50` / `W32N55`) bound
  to your NIC, used to send/receive raw EAPOL frames;
* runs a `LocalSystem` service that creates processes in your session, writes to
  Winlogon, etc.;
* loads a packet-capture driver that game anti-cheats (Tencent ACE, BattlEye,
  EAC, Vanguard…) actively watch for.

If all you need is to authenticate an 802.1X port, you don't need any of that.
RJNMSL gives you two ways to do it.

---

## Two ways to authenticate

### 1. `eapmd5` — native 802.1X + a user-mode EAP-MD5 plugin (recommended)

Windows' built-in supplicant (`Wired AutoConfig` / `dot3svc`) already speaks
802.1X/EAPOL through the normal NDIS stack. The only missing piece is an
**EAP-MD5** implementation — Microsoft removed its own after Vista. RJNMSL
provides one as a small **user-mode EapHost peer method DLL** (`eapmd5.dll`).

```
your process ──► dot3svc / OneX ──► EapHost ──► eapmd5.dll   (computes MD5)
                                     │
                                     └─ EAPOL framing handled by Windows NDIS
                                        (Realtek/Intel/… miniport)
```

* **No packet-capture driver, no vendor service.** Nothing extra in kernel space.
* The DLL never touches raw Ethernet — it only fills in the EAP payload.
* Anti-cheat friendly: there is no L2 injection anywhere.

### 2. `rj8021x` — standalone supplicant over Npcap

A from-scratch 802.1X supplicant that sends/parses EAPOL frames itself via
Npcap. Supports **EAP-MD5** and (behind a feature flag) **EAP-PEAP/MSCHAPv2**.

* Useful when `dot3svc` is unavailable/unwanted, or for protocol debugging.
* Requires Npcap and an Administrator process.
* Because it *does* use a packet-capture driver, it carries the same
  anti-cheat caveats as any raw-L2 tool.

**If your goal is "play games without the anti-cheat complaining", use `eapmd5`.**

---

## Quick start — `eapmd5`

Requirements: Windows 10/11, Rust (MSVC toolchain), Administrator.

```powershell
git clone https://github.com/USERNAME/RJNMSL
cd RJNMSL
cargo build --release --workspace          # produces target\release\eapmd5.dll

# from an elevated PowerShell:
.\scripts\install.ps1
```

The installer will:

1. copy `eapmd5.dll` to `System32` and register it under
   `HKLM\SYSTEM\CurrentControlSet\Services\EapHost\Methods\49374\4`;
2. set `dot3svc` to Automatic and install an 802.1X LAN profile;
3. store your credentials;
4. disable the Ruijie supplicant (`RJSuService`) unless `-KeepVendorSupplicant`;
5. stop Npcap unless `-KeepNpcap`.

Verify:

```powershell
netsh lan show interfaces        # -> "Connected. Authentication succeeded."
```

Undo everything:

```powershell
.\scripts\uninstall.ps1 -RestoreVendorSupplicant
```

### Where credentials live

The method reads `C:\ProgramData\RJNMSL\eapmd5.ini`:

```ini
username=your-account
password=your-password
```

`install.ps1` writes it and restricts its ACL to `SYSTEM` + `Administrators`.
You can also pass `-Username` / `-Password`, or drop a git-ignored
`credentials.txt` in the repo root.

---

## Quick start — `rj8021x`

Requirements: [Npcap](https://npcap.com), Rust (MSVC), Administrator.

```powershell
# Npcap ships no import libraries; generate them once from an x64 VS prompt:
.\scripts\gen-npcap-libs.ps1

cargo build -p rj8021x --release
copy crates\rj8021x\config.toml.example config.toml   # edit it
target\release\rj8021x.exe --list                     # find your NIC
target\release\rj8021x.exe --config config.toml       # run elevated
```

See [`crates/rj8021x/`](crates/rj8021x/) and the config example for options.
PEAP is opt-in: `cargo build -p rj8021x --release --features peap`.

---

## Repository layout

```
crates/
  eapmd5/          user-mode EapHost EAP-MD5 (Type 4) peer method  (cdylib)
  rj8021x/         standalone 802.1X supplicant over Npcap        (bin)
scripts/
  install.ps1      install the EapHost method + native 802.1X
  uninstall.ps1    revert everything
  gen-npcap-libs.ps1  build wpcap.lib / Packet.lib from the Npcap runtime
docs/
  architecture.md  how the native path works + EapHost ABI notes
  troubleshooting.md  diagnostics and known Windows issues
```

---

## Caveats

* **EAP-MD5 is weak** (no server authentication, offline dictionary attacks).
  RJNMSL does not make the protocol stronger; it just gives Windows a Type-4
  implementation. If you control the RADIUS/NAC side, migrate to PEAP/TEAP.
* The credential file is **plaintext** (ACL-restricted). Anyone with local admin
  can read it.
* If you use `rj8021x`, **stop the vendor supplicant and Windows' own
  `dot3svc`** while it runs, or they will fight over the port.
* Windows 11 24H2 has public reports of third-party EAP method regressions.
  See [`docs/troubleshooting.md`](docs/troubleshooting.md).

## License

MIT — see [`LICENSE`](LICENSE). Provided for interoperability with your own
network; respect your institution's acceptable-use policy.