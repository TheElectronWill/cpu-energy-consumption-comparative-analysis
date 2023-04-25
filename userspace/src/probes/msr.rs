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

pub enum RaplVendor {
    Intel,
    Amd,
}

/// Reads the RAPL MSR values (via /dev/cpu/<cpu_id>/msr for one CPU per socket).
pub struct MsrProbe {
    msr: Vec<RaplMsrAccess>,

    /// The MSR RAPL registers to read for each descriptor
    domain_registers: Vec<Addr>,
}

struct RaplMsrAccess {
    /// File descriptor to the MSR sysfs for one cpu
    fd: File,
    /// RAPL energy unit
    energy_unit: f32,
    /// CPU (core) id
    cpu_id: u32,
}

impl MsrProbe {
    pub fn new(socket_cpus: &Vec<u32>, vendor: &RaplVendor) -> io::Result<MsrProbe> {
        let msr = socket_cpus
            .iter()
            .map(|cpu| {
                let path = format!("/dev/cpu/{cpu}/msr");
                let fd = File::open(path)?;
                let energy_unit = read_energy_unit(&fd, vendor)?;
                Ok(RaplMsrAccess {
                    fd,
                    energy_unit,
                    cpu_id: *cpu,
                })
            })
            .collect::<io::Result<Vec<RaplMsrAccess>>>()?;

        let domain_registers = match vendor {
            RaplVendor::Intel => {
                vec![
                    intel::MSR_PKG_ENERGY_STATUS,
                    // intel::MSR_PP0_ENERGY_STATUS,
                    // intel::MSR_PP1_ENERGY_STATUS,
                    // intel::MSR_DRAM_ENERGY_STATUS,
                    // intel::MSR_PLATFORM_ENERGY_STATUS,
                ]
            }
            RaplVendor::Amd => {
                vec![
                    amd::MSR_PKG_ENERGY_STATUS,
                    // amd::MSR_CORE_ENERGY_STATUS
                ]
            }
        };
        Ok(MsrProbe { msr, domain_registers })
    }
}

impl super::Probe for MsrProbe {
    fn read_uj(&mut self, out: &mut Vec<super::EnergyMeasurement>) -> anyhow::Result<()> {
        for msr in &self.msr {
            for reg in &self.domain_registers {
                let value = read_msr(&msr.fd, *reg)?;
                let joules = (value as f32) * msr.energy_unit;
                let microjoules = (joules * 1000_000.0) as u64;
                out.push(super::EnergyMeasurement {
                    energy_counter: microjoules,
                    cpu: msr.cpu_id,
                })
            }
        }
        Ok(())
    }
}

fn read_msr(msr: &File, at: Addr) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    msr.read_exact_at(&mut buf, at)?;
    Ok(u64::from_ne_bytes(buf))
}

fn read_energy_unit(msr: &File, vendor: &RaplVendor) -> io::Result<f32> {
    let offset = match vendor {
        RaplVendor::Intel => intel::MSR_RAPL_POWER_UNIT,
        RaplVendor::Amd => amd::MSR_RAPL_POWER_UNIT,
    };
    let msr_value = read_msr(msr, offset)?;

    // According to Intel's manual, the value we're interested in is
    // "energy status unit" at bits 12:8 (mask 0x1F00)
    let esu = (msr_value & 0x1F00) >> 8;

    // The energy unit, aka "multiplier", is 1/(2^esu) = (1/2)^esu
    // This means that when we read an energy value from MSR, the actual value is
    // `msr_value * multiplier` Joules.
    let multiplier = 0.5_f32.powi(esu as i32);
    Ok(multiplier)
}

pub fn get_cpu_vendor() -> anyhow::Result<RaplVendor> {
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
