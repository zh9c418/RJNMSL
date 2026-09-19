# Third-party notices

RJNMSL itself is licensed **GPL-3.0-only** (see [`LICENSE`](LICENSE)).

It builds on the components below. All Rust crate dependencies are distributed
under permissive licenses (MIT / Apache-2.0 / ISC / BSD / Unlicense); none add
copyleft obligations beyond attribution. Versions are those pinned in
[`Cargo.lock`](Cargo.lock) at the time of writing.

## Direct dependencies

| Crate | Used by | License |
|---|---|---|
| `md-5` | eapmd5, rj8021x | MIT OR Apache-2.0 |
| `anyhow` | rj8021x | MIT OR Apache-2.0 |
| `log` | rj8021x | MIT OR Apache-2.0 |
| `env_logger` | rj8021x | MIT OR Apache-2.0 |
| `clap` | rj8021x | MIT OR Apache-2.0 |
| `serde` | rj8021x | MIT OR Apache-2.0 |
| `toml` | rj8021x | MIT OR Apache-2.0 |
| `pcap` | rj8021x | MIT OR Apache-2.0 |
| `hex` | rj8021x | MIT OR Apache-2.0 |
| `sha1` | rj8021x (peap) | MIT OR Apache-2.0 |
| `md4` | rj8021x (peap) | MIT OR Apache-2.0 |
| `des` | rj8021x (peap) | MIT OR Apache-2.0 |
| `rand` | rj8021x (peap) | MIT OR Apache-2.0 |
| `rustls` | rj8021x (peap) | Apache-2.0 OR ISC OR MIT |

## Transitive dependencies

| Crate | Version | License |
|---|---|---|
| aho-corasick | 1.1.5 | Unlicense OR MIT |
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.14 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 |
| bitflags | 1.3.2 | MIT/Apache-2.0 |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| cc | 1.4.7 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| cipher | 0.4.4 | MIT OR Apache-2.0 |
| clap_builder | 4.6.7 | MIT OR Apache-2.0 |
| clap_derive | 4.6.7 | MIT OR Apache-2.0 |
| clap_lex | 1.1.1 | MIT OR Apache-2.0 |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| defmt | 1.1.1 | MIT OR Apache-2.0 |
| defmt-macros | 1.1.1 | MIT OR Apache-2.0 |
| defmt-parser | 1.0.0 | MIT OR Apache-2.0 |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| env_filter | 2.0.0 | MIT OR Apache-2.0 |
| equivalent | 1.0.2 | Apache-2.0 OR MIT |
| errno | 0.2.8 | MIT/Apache-2.0 |
| errno-dragonfly | 0.1.2 | MIT |
| find-msvc-tools | 0.1.13 | MIT OR Apache-2.0 |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| indexmap | 2.14.2 | Apache-2.0 OR MIT |
| inout | 0.1.4 | MIT OR Apache-2.0 |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| jiff | 0.2.37 | Unlicense OR MIT |
| jiff-core | 0.1.1 | Unlicense OR MIT |
| jiff-static | 0.2.37 | Unlicense OR MIT |
| libc | 0.2.189 | MIT OR Apache-2.0 |
| libloading | 0.8.9 | ISC |
| memchr | 2.8.3 | Unlicense OR MIT |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| pkg-config | 0.3.34 | MIT OR Apache-2.0 |
| portable-atomic | 1.15.0 | Apache-2.0 OR MIT |
| portable-atomic-util | 0.2.8 | Apache-2.0 OR MIT |
| ppv-lite86 | 0.2.21 | MIT OR Apache-2.0 |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| rand_chacha | 0.3.1 | MIT OR Apache-2.0 |
| rand_core | 0.6.4 | MIT OR Apache-2.0 |
| regex | 1.13.1 | MIT OR Apache-2.0 |
| regex-automata | 0.4.18 | MIT OR Apache-2.0 |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 |
| ring | 0.17.14 | Apache-2.0 AND ISC |
| rustls-pki-types | 1.15.1 | MIT OR Apache-2.0 |
| rustls-webpki | 0.103.15 | ISC |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| serde_spanned | 0.6.9 | MIT OR Apache-2.0 |
| shlex | 2.0.1 | MIT OR Apache-2.0 |
| strsim | 0.11.1 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 2.0.119 / 3.0.6 | MIT OR Apache-2.0 |
| thiserror | 2.0.20 | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.20 | MIT OR Apache-2.0 |
| toml_datetime | 0.6.11 | MIT OR Apache-2.0 |
| toml_edit | 0.22.27 | MIT OR Apache-2.0 |
| toml_write | 0.1.2 | MIT OR Apache-2.0 |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| untrusted | 0.9.0 | ISC |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| wasi | 0.11.1 | Apache-2.0 OR MIT |
| winapi / -i686-… / -x86_64-… | 0.3.9 / 0.4.0 | MIT/Apache-2.0 |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-sys | 0.36.1 / 0.52.0 / 0.61.2 | MIT OR Apache-2.0 |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 |
| windows_* (arch targets) | 0.36.1 / 0.52.6 | MIT OR Apache-2.0 |
| winnow | 0.7.15 | MIT |
| zerocopy | 0.8.57 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zerocopy-derive | 0.8.57 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zeroize | 1.9.0 | Apache-2.0 OR MIT |

## Npcap (runtime component of `rj8021x` only)

`rj8021x` loads Npcap's `wpcap.dll` and `Packet.dll` **at runtime** and links
against import stubs. **Npcap itself is not bundled or redistributed by this
project.**

* Copyright © 2013–2024 Nmap Software LLC.
* License: <https://npcap.com/oem/license/> — the free edition allows
  personal/non-commercial use and restricts redistribution; commercial/OEM use
  requires a separate license.
* Download/install it yourself from <https://npcap.com>.

The `crates/rj8021x/.npcap/wpcap.lib` and `Packet.lib` files in this repository
are **import stubs generated from the locally installed Npcap DLLs** (see
[`scripts/gen-npcap-libs.ps1`](scripts/gen-npcap-libs.ps1)); they contain no
Npcap code.

## Windows / Microsoft SDK

The native path (`eapmd5`) uses the documented Windows **EAPHost** API and
`kernel32` / `crypt32` system calls. The `eapmd5` crate's type definitions are
derived from the Windows SDK headers (`eapmethodpeerapis.h`, `eaptypes.h`,
`eapmethodtypes.h`), used under the Microsoft Software License Terms.

## Regenerating this list

```sh
# list crate licenses from the local registry cache
awk '/^\[\[package\]\]/{n="";v=""} /^name = "/{n=$0;sub(/^name = "/,"",n);sub(/"$/,"",n)} \
     /^version = "/{v=$0;sub(/^version = "/,"",v);sub(/"$/,"",v)} \
     /^source = "registry/{print n" "v}' Cargo.lock
```

or use [`cargo-about`](https://github.com/EmbarkStudios/cargo-about) /
[`cargo-license`](https://github.com/onur/cargo-license).