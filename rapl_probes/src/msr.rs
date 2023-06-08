// According to Intel 64 and IA-32 architectures software developer's manual, volume 3B,
// MSR_PKG_ENERGY_STATUS reports the measured energy usage of the package.

use std::{
    fs::File,
    io,
    os::unix::prelude::FileExt,
    process::{Command, Stdio},
};

use anyhow::{anyhow, Context};
use regex::Regex;

use crate::EnergyMeasurements;

use super::{CpuId, EnergyProbe, RaplDomainType};

type Addr = u64;

/// MSR registers' addresses for Intel RAPL domains
mod intel {
    use super::Addr;

    pub const MSR_RAPL_POWER_UNIT: Addr = 0x00000606;
    pub const MSR_PKG_ENERGY_STATUS: Addr = 0x00000611;
    pub const MSR_PP0_ENERGY_STATUS: Addr = 0x00000639;
    pub const MSR_PP1_ENERGY_STATUS: Addr = 0x00000641;
    pub const MSR_DRAM_ENERGY_STATUS: Addr = 0x00000619;
    pub const MSR_PLATFORM_ENERGY_STATUS: Addr = 0x0000064D;
}

/// MSR registers' addresses for AMD RAPL domains
mod amd {
    use super::Addr;

    pub const MSR_RAPL_POWER_UNIT: Addr = 0xc0010299;
    pub const MSR_CORE_ENERGY_STATUS: Addr = 0xc001029a;
    pub const MSR_PKG_ENERGY_STATUS: Addr = 0xc001029b;
}

/// Mask to apply when reading the energy values
const MSR_ENERGY_MASK: Addr = 0xffffffff;

/// Maximum value of the MSR counter.
/// Note that this technically depends on the exact hardware, but for our purposes it's good enough.
const MSR_MAX_ENERGY: u64 = u32::MAX as u64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RaplVendor {
    Intel,
    Amd,
}

/// Reads the RAPL MSR values (via /dev/cpu/<cpu_id>/msr for one CPU per socket).
pub struct MsrProbe {
    /// Stores the energy measurements
    measurements: EnergyMeasurements,

    /// MSR file descriptors for each cpu
    msr_per_cpu: Vec<RaplMsrAccess>,

    /// The MSR RAPL registers to read for each descriptor
    domains: Vec<RaplMsrDomain>,
}

struct RaplMsrDomain {
    domain: RaplDomainType,
    addr: Addr,
}

struct RaplMsrAccess {
    /// File descriptor to the MSR sysfs for one cpu
    fd: File,
    /// RAPL energy unit (a f32 would be enough but we only do f64-math with it)
    energy_unit: f64,
    /// Socket id
    socket_id: u32,
}

impl EnergyProbe for MsrProbe {
    fn poll(&mut self) -> anyhow::Result<()> {
        for msr in &mut self.msr_per_cpu {
            for RaplMsrDomain { domain, addr } in &self.domains {
                let msr_value = read_msr(&msr.fd, *addr)
                    .with_context(|| format!("failed to read MSR {addr} for domain {domain:?}"))?;

                let counter_value = msr_value & MSR_ENERGY_MASK;

                self.measurements
                    .push(msr.socket_id, *domain, counter_value, MSR_MAX_ENERGY, msr.energy_unit);
            }
        }
        Ok(())
    }

    fn measurements(&self) -> &EnergyMeasurements {
        &self.measurements
    }
    
    fn reset(&mut self) {
        self.measurements.clear()
    }
}

impl MsrProbe {
    pub fn new(cpus: &[CpuId], domains: &[RaplDomainType]) -> anyhow::Result<MsrProbe> {
        crate::check_socket_cpus(cpus)?;
        let vendor = cpu_vendor()?;
        let msr_per_cpu = cpus
            .iter()
            .map(|CpuId { socket, cpu }| {
                let path = format!("/dev/cpu/{cpu}/msr");
                let fd = File::open(path)?;
                let energy_unit = read_energy_unit(&fd, vendor)? as f64;
                Ok(RaplMsrAccess {
                    fd,
                    energy_unit,
                    socket_id: *socket,
                })
            })
            .collect::<io::Result<Vec<RaplMsrAccess>>>()?;

        let domains = domains
            .iter()
            .map(|d| {
                Ok(RaplMsrDomain {
                    domain: *d,
                    addr: domain_msr_address(*d, vendor).context("RAPL domain should exist in MSR")?,
                })
            })
            .collect::<anyhow::Result<Vec<RaplMsrDomain>>>()?;

        Ok(MsrProbe {
            measurements: EnergyMeasurements::new(cpus.len()),
            msr_per_cpu,
            domains,
        })
    }
}

fn read_msr(msr: &File, at: Addr) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    msr.read_exact_at(&mut buf, at)?;
    Ok(u64::from_ne_bytes(buf))
}

/// Extract the energy unit from the Model Specific Register `msr`.
///
/// # Wrong values
///
/// Note that the returned energy unit may not apply for all measurements,
/// because some architectures use a different unit for some domains (e.g. DRAM).
/// This is platform-dependent, and I do not wish to implement all of them here.
///
/// See [Linux source code - rapl.c](https://github.com/torvalds/linux/blob/0036fb00a756a2f6e360d44e2e3d2200a8afbc9b/arch/x86/events/rapl.c#L612)
///
fn read_energy_unit(msr: &File, vendor: RaplVendor) -> io::Result<f32> {
    let offset = match vendor {
        RaplVendor::Intel => intel::MSR_RAPL_POWER_UNIT,
        RaplVendor::Amd => amd::MSR_RAPL_POWER_UNIT,
    };
    let msr_value = read_msr(msr, offset)?;

    // According to the Intel Software Developer manual, the value we're interested in is
    // "energy status unit" at bits 12:8 (mask 0x1F00)
    let esu = (msr_value & 0x1F00) >> 8;

    // The energy unit, aka "multiplier", is 1/(2^esu) = (1/2)^esu
    // This means that when we read an energy value from MSR, the actual value is
    // `msr_value * multiplier` Joules.
    let multiplier = 0.5_f32.powi(esu as i32);
    Ok(multiplier)
}

pub fn cpu_vendor() -> anyhow::Result<RaplVendor> {
    // run: LC_ALL=C lscpu
    let child = Command::new("lscpu")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .spawn()
        .context("lscpu should be executable")?;
    let finished = child.wait_with_output()?;
    let stdout = std::str::from_utf8(&finished.stdout)?;

    // find the Vendor ID
    let vendor_regex = Regex::new(r"Vendor ID:\s+(\w+)")?;
    let group = vendor_regex
        .captures(stdout)
        .context("vendor id not found in lscpu output")?
        .get(1)
        .unwrap();
    let vendor = group.as_str().trim();

    // turn it into the right enum variant
    match vendor {
        "AuthenticAMD" => Ok(RaplVendor::Amd),
        "GenuineIntel" => Ok(RaplVendor::Intel),
        _ => Err(anyhow!("Unsupported CPU vendor {vendor}")),
    }
}

pub fn domain_msr_address(domain: RaplDomainType, vendor: RaplVendor) -> Option<Addr> {
    match vendor {
        RaplVendor::Intel => match domain {
            RaplDomainType::Package => Some(intel::MSR_PKG_ENERGY_STATUS),
            RaplDomainType::PP0 => Some(intel::MSR_PP0_ENERGY_STATUS),
            RaplDomainType::PP1 => Some(intel::MSR_PP1_ENERGY_STATUS),
            RaplDomainType::Dram => Some(intel::MSR_DRAM_ENERGY_STATUS),
            RaplDomainType::Platform => Some(intel::MSR_PLATFORM_ENERGY_STATUS),
        },
        RaplVendor::Amd => match domain {
            RaplDomainType::Package => Some(amd::MSR_PKG_ENERGY_STATUS),
            RaplDomainType::PP0 => Some(amd::MSR_CORE_ENERGY_STATUS),
            RaplDomainType::PP1 => None,
            RaplDomainType::Dram => None,
            RaplDomainType::Platform => None,
        },
    }
}

pub fn all_domains(vendor: RaplVendor) -> Vec<RaplDomainType> {
    match vendor {
        RaplVendor::Intel => vec![
            RaplDomainType::Package,
            RaplDomainType::PP0,
            RaplDomainType::PP1,
            RaplDomainType::Dram,
            RaplDomainType::Platform,
        ],
        RaplVendor::Amd => vec![RaplDomainType::Package, RaplDomainType::PP0],
    }
}
