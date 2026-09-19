//! Npcap device discovery and raw Ethernet send/receive.
//!
//! `pcap` 2.x does not expose the adapter MAC address, so on Windows we query
//! it from `GetAdaptersAddresses` by matching the adapter GUID that Npcap puts
//! in the device name (`\Device\NPF_{GUID}`).

use anyhow::{bail, Context, Result};
use pcap::{Active, Capture, Device};

use crate::eth::{fmt_mac, parse_mac};

/// Pull the `{GUID}` out of a pcap device name.
fn extract_guid(name: &str) -> Option<String> {
    let start = name.find('{')?;
    let end = name[start..].find('}')? + start;
    Some(name[start..=end].to_string())
}

#[cfg(windows)]
mod win {
    use std::ffi::{c_void, CStr};
    use std::os::raw::c_char;

    #[repr(C)]
    struct IpAdapterAddresses {
        length: u32,
        if_index: u32,
        next: *mut IpAdapterAddresses,
        adapter_name: *mut c_char, // PCHAR, e.g. "{GUID}"
        first_unicast: *mut c_void,
        first_anycast: *mut c_void,
        first_multicast: *mut c_void,
        first_dns: *mut c_void,
        dns_suffix: *mut u16,
        description: *mut u16,
        friendly_name: *mut u16,
        physical_address: [u8; 8],
        physical_address_length: u32,
        // fields beyond this point are not needed
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *mut c_void,
            addresses: *mut IpAdapterAddresses,
            size: *mut u32,
        ) -> u32;
    }

    const AF_UNSPEC: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;

    pub fn mac_for_guid(guid: &str) -> Option<[u8; 6]> {
        unsafe {
            let mut size: u32 = 32 * 1024;
            let mut buf: Vec<u8> = vec![0u8; size as usize + 16];

            loop {
                let ret = GetAdaptersAddresses(
                    AF_UNSPEC,
                    0,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr() as *mut IpAdapterAddresses,
                    &mut size,
                );
                if ret == 0 {
                    break;
                }
                if ret == ERROR_BUFFER_OVERFLOW {
                    buf = vec![0u8; size as usize + 16];
                    continue;
                }
                return None;
            }

            let mut p = buf.as_ptr() as *const IpAdapterAddresses;
            while !p.is_null() {
                let a = &*p;
                if !a.adapter_name.is_null() {
                    if let Ok(name) = CStr::from_ptr(a.adapter_name).to_str() {
                        if name.eq_ignore_ascii_case(guid) {
                            let n = a.physical_address_length.min(6) as usize;
                            if n == 6 {
                                let mut m = [0u8; 6];
                                m.copy_from_slice(&a.physical_address[..6]);
                                return Some(m);
                            }
                        }
                    }
                }
                p = a.next;
            }
            None
        }
    }
}

/// Best-effort MAC lookup for a pcap device.
fn device_mac(dev: &Device) -> Option<[u8; 6]> {
    #[cfg(windows)]
    {
        let guid = extract_guid(&dev.name)?;
        win::mac_for_guid(&guid)
    }
    #[cfg(not(windows))]
    {
        let _ = dev;
        None
    }
}

fn score(dev: &Device, spec: &str) -> u32 {
    if dev.name.eq_ignore_ascii_case(spec) {
        return 1000;
    }
    if let Some(mac) = parse_mac(spec) {
        if device_mac(dev) == Some(mac) {
            return 900;
        }
    }
    let sl = spec.to_lowercase();
    if let Some(desc) = &dev.desc {
        if desc.to_lowercase().contains(&sl) {
            return 500;
        }
    }
    if dev.name.to_lowercase().contains(&sl) {
        return 300;
    }
    0
}

pub fn find_device(spec: &str) -> Result<Device> {
    let devices = Device::list().context("pcap Device::list() failed")?;
    let mut best: Option<Device> = None;
    let mut best_score = 0u32;
    for dev in devices {
        let s = score(&dev, spec);
        if s > best_score {
            best_score = s;
            best = Some(dev);
        }
    }
    match best {
        Some(dev) => Ok(dev),
        None => bail!("no pcap interface matches {spec:?}; run with --list to see options"),
    }
}

pub fn list_devices() -> Result<()> {
    let devices = Device::list().context("pcap Device::list() failed")?;
    if devices.is_empty() {
        println!("(no pcap devices found - is Npcap installed?)");
    }
    for dev in devices {
        println!("{}", dev.name);
        if let Some(desc) = &dev.desc {
            println!("    desc : {desc}");
        }
        if let Some(mac) = device_mac(&dev) {
            println!("    mac  : {}", fmt_mac(&mac));
        }
    }
    Ok(())
}

pub struct Link {
    pub cap: Capture<Active>,
    pub local_mac: [u8; 6],
    pub dev_name: String,
}

impl Link {
    pub fn open(spec: &str, mac_override: Option<[u8; 6]>) -> Result<Link> {
        let dev = find_device(spec)?;
        let dev_name = dev.name.clone();

        let mut local_mac = device_mac(&dev).unwrap_or([0u8; 6]);
        if let Some(m) = mac_override {
            local_mac = m;
        }
        if local_mac == [0u8; 6] {
            bail!("could not determine MAC address for {dev_name}; set `local_mac` in the config");
        }

        let mut cap = Capture::from_device(dev.name.as_str())
            .context("Capture::from_device failed")?
            .promisc(true)
            .immediate_mode(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .context("failed to open pcap capture (run as Administrator?)")?;

        log::info!("datalink: {:?}", cap.get_datalink());
        cap.filter("ether proto 0x888e", true)
            .context("failed to install BPF filter `ether proto 0x888e`")?;

        Ok(Link {
            cap,
            local_mac,
            dev_name,
        })
    }

    pub fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.cap.sendpacket(frame).context("sendpacket failed")?;
        Ok(())
    }

    /// Receive one frame. `Ok(None)` means the read timed out.
    pub fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        match self.cap.next_packet() {
            Ok(p) => Ok(Some(p.data.to_vec())),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("pcap recv error: {e}")),
        }
    }
}
