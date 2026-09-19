# Troubleshooting

## Native path (`eapmd5`)

Start here:

```powershell
netsh lan show interfaces                       # port state
netsh lan show profiles interface="Ethernet"    # is our EAP type applied?
Get-Content C:\ProgramData\RJNMSL\eapmd5.log -Tail 40
```

`Wired AutoConfig` records the real reason:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Wired-AutoConfig/Operational' -MaxEvents 10 |
    Select-Object TimeCreated, Id, Message | Format-List
```

### "Identity: NULL" + error `0x80420014`

`0x80420014` is `EAP_E_EAPHOST_IDENTITY_UNKNOWN`.

If the method log shows **only `GetInfo`** and never `Initialize`, EapHost
rejected the dispatch table. Almost always this is the
**`EapPeerGetIdentity` vs `EapPeerSetCredentials` exclusivity bug** — see
[architecture.md](architecture.md#two-things-that-will-bite-you). Make sure
exactly one of them is non-NULL.

If the method log shows `GetIdentity` but no `BeginSession`, or the sign-in
notification opens **Settings** instead of a credential dialog, you are hitting
the Windows third-party-EAP issue below.

### "Credentials Configured: No"

OneX will not start a session. Re-run `scripts\install.ps1` (it calls
`netsh lan set eapuserdata`), or:

```powershell
netsh lan set eapuserdata filename="creds.xml" allusers=yes interface="Ethernet"
```

The XML only needs to be well-formed; our `EapPeerCredentialsXml2Blob` ignores
its content.

### The method DLL is not visible in the Settings app

Windows 11's *Settings → Network → Ethernet → authentication* dropdown only
lists Microsoft's inbox EAP methods. Third-party methods appear in the **classic**
adapter dialog: `ncpa.cpl` → adapter → *Properties* → *Authentication*. (You can
still configure the profile entirely with `netsh lan`.)

### Windows 11 24H2 / third-party EAP regressions

There are public reports (Microsoft Q&A) of third-party EAP methods that work on
Windows 10 and early Windows 11 but fail on **24H2** and after **KB5062660**:

* the DLL loads, `EapPeerGetInfo` (sometimes `GetIdentity`) runs, but
  `EapPeerBeginSession` is never called;
* `eap3host.exe` / the `Microsoft ThirdPartyEapDispatcher` (`eapp3hst.dll`)
  behaves inconsistently;
* the "Sign in" notification opens Settings, which cannot collect credentials
  for a third-party method.

Useful diagnostics:

```powershell
winver                    # check build (24H2 = 26100+)
Get-Process Eap3Host, dllhost -ErrorAction SilentlyContinue
Get-Service dot3svc, eaphost
```

There is no documented switch to force the legacy credential UI. A registry
value `ThirdPartyEapDispatcherPeerConfig` under
`HKLM\SYSTEM\CurrentControlSet\Services\EapHost` has been suggested in support
threads but is undocumented and did not help everyone. If you are affected,
fall back to `rj8021x`.

---

## Standalone path (`rj8021x`)

### `exit=127` / the exe exits immediately

`wpcap.dll` / `Packet.dll` were not found. Npcap's runtime DLLs live in
`C:\Windows\System32\Npcap`, which is not on `PATH`. Either add it to `PATH`,
copy the two DLLs next to the exe, or reinstall Npcap in WinPcap-compatible mode
(DLLs land in `System32`).

### `--list` shows only `\Device\NPF_Loopback`

The Npcap driver is not bound to any physical adapter (the `npcap` service may be
missing or a conflicting packet driver is installed). Reinstall Npcap. Common
conflicts are other WinPcap clones (some game accelerators install one).

### `sendpacket failed` / no reply from the switch

* Run elevated.
* Make sure nothing else is authenticating on the same NIC — stop the Ruijie
  service (and Windows' own `dot3svc` if it is also enabled).
* Verify the interface selection with `--list` and the `interface` config value.

### Everything times out, nothing is received

A 600 s block timer is applied to the adapter after a failed attempt. Restart
`dot3svc` (native path) or just wait; `netsh lan reconnect` may not clear it.

---

## General

* `netsh lan` commands require `dot3svc` to be **running**.
* After any failed attempt, `Wired AutoConfig` may suspend retries for 10 min
  (`Network authentication attempts have been temporarily suspended …`).
  Restarting `dot3svc` allows an immediate retry.
* The method log is append-only and not rotated — delete
  `C:\ProgramData\RJNMSL\eapmd5.log` freely.