# Architecture

## The native path (`eapmd5`)

```
  ┌─────────────┐   EAP payload    ┌──────────┐   EAPOL     ┌──────────────┐
  │ eapmd5.dll  │ ◄──────────────► │ EapHost  │ ◄─────────► │ dot3svc/OneX │
  │ (user mode) │                  │ (svchost)│             │  (svchost)   │
  └─────────────┘                  └──────────┘             └──────┬───────┘
                                                                   │ EAPOL frames
                                                                   ▼
                                                          Windows NDIS → NIC driver
```

`eapmd5.dll` is a **peer method**: it only implements the EAP state machine for
one EAP type. Everything below it — EAPOL framing, retransmission, the port
state machine — is Windows' job. That is exactly why this path needs no
packet-capture driver.

### EapHost peer-method lifecycle

The host calls, in order:

```
EapPeerGetInfo              fill EAP_PEER_METHOD_ROUTINES (the dispatch table)
EapPeerInitialize           once per process
EapPeerGetIdentity          get the identity (+ optional user-data blob)
EapPeerBeginSession         create per-session state
EapPeerProcessRequestPacket host hands us an EAP-Request
EapPeerGetResponsePacket    we hand back an EAP-Response
   … repeat …
EapPeerGetResult            final success/failure
EapPeerEndSession
EapPeerShutdown
```

Config/credential converters (`EapPeerConfigXml2Blob`,
`EapPeerCredentialsXml2Blob`, …) are separate exports used by
`netsh lan`, MDM/GPO and the profile UI — **not** part of the runtime dispatch
table.

### Registration

```
HKLM\SYSTEM\CurrentControlSet\Services\EapHost\Methods\<AuthorId>\<EapType>
    PeerDllPath               REG_EXPAND_SZ  full path to the DLL
    PeerFriendlyName          REG_SZ
    PeerInvokeUsernameDialog  REG_DWORD      0 (we use GetIdentity)
    PeerInvokePasswordDialog  REG_DWORD      0
    Properties                REG_DWORD      capability bitmap
```

`AuthorId` is an author-defined id (we use `49374` / `0xC0DE`); `EapType` is `4`
for MD5-Challenge. `Properties` is "recommended"; the value `0x173cf8bf` is what
a comparable inbox method uses.

### Two things that will bite you

Both were found the hard way; they are the difference between "EapHost loads the
DLL, calls `EapPeerGetInfo`, then silently gives up" and a working method.

1. **`EapPeerGetIdentity` and `EapPeerSetCredentials` are mutually exclusive.**
   The header says it in one line:

   > A method exports *either* `EapPeerGetIdentity` (and `EapPeerInvokeIdentityUI`)
   > *or* `EapPeerSetCredentials` (and sets the `InvokeUserNameDlg` regkey).

   Put **one** of them in the dispatch table and set the other to `NULL`.
   Setting both non-NULL makes EapHost reject the table right after
   `EapPeerGetInfo`, and you never see `EapPeerInitialize`.
   (`EapPeerSetCredentials` also *takes a session handle*, so it can only be
   called after `BeginSession` — using `GetIdentity` avoids that dependency.)

2. **Match the SDK sample for `dwVersion` / `pEapType`.** The Windows SDK's
   `EAPHost client method sample` does:

   ```c
   ZeroMemory(pEapInfo, sizeof(EAP_PEER_METHOD_ROUTINES));
   pEapInfo->dwVersion = 1;
   //pEapInfo->pEapType = ;          // left NULL
   pEapInfo->EapPeerInitialize   = SdkEapPeerInitialize;
   pEapInfo->EapPeerBeginSession = SdkEapPeerBeginSession;
   pEapInfo->EapPeerGetIdentity  = SdkEapPeerGetIdentity;
   pEapInfo->EapPeerSetCredentials = NULL;
   ...
   ```

   `dwVersion` is implementer-defined (Microsoft does not define values), but
   `1` matches the sample.

### The EAP-MD5 math

```
EAP-Request/MD5-Challenge:  Type=4 | Value-Size | Challenge | Name
EAP-Response/MD5:           Type=4 | 16 | MD5( Identifier | Password | Challenge )
```

The `Identifier` is the EAP packet's `Id` byte. That's the whole method.

### Credentials

OneX refuses to start an EAP session while the profile has
`Credentials Configured: No`. There is no UI for third-party methods on modern
Windows, so the installer feeds EapHost a credential blob via
`netsh lan set eapuserdata`, which calls our `EapPeerCredentialsXml2Blob`.
That blob is a placeholder — the real username/password are read from
`C:\ProgramData\RJNMSL\eapmd5.ini`.

---

## The standalone path (`rj8021x`)

```
config.toml ─► rj8021x ─► Npcap (wpcap.dll) ─► NIC
                    ▲
                    └─ EAPOL framing, EAP state machine, EAP-MD5 / EAP-PEAP
```

* `eth.rs` / `eapol.rs` / `eap.rs` — frame and packet codecs, EAP-MD5.
* `supplicant.rs` — initiate (`EAPOL-Start`) → authenticate → maintain/re-auth.
* `peap.rs` + `mschapv2.rs` — optional EAP-PEAP/MSCHAPv2 over rustls.
* `pcap_io.rs` — device discovery (by name / MAC / description) and raw send/recv.

Because it sends raw Ethernet itself, it needs Npcap (a packet-capture driver)
and elevated privileges — hence the anti-cheat caveat in the README.