use anyhow::{Context, Result};
use log::debug;
use perf_event_open_sys as sys;
use std::{
    fs::{self, File},
    io::{self, Read},
    os::fd::FromRawFd,
    path::Path,
};

use crate::EnergyMeasurements;

use super::{CpuId, EnergyProbe, RaplDomainType};

// See https://github.com/torvalds/linux/commit/4788e5b4b2338f85fa42a712a182d8afd65d7c58
// for an explaination of the RAPL PMU driver.

pub(crate) const PERF_MAX_ENERGY: u64 = u64::MAX;

#[derive(Debug)]
pub struct PowerEvent {
    /// The name of the power event, as reported by the sysfs. This corresponds to a RAPL **domain name**, like "pkg".
    pub name: String,
    /// The RAPL domain type, as an enum.
    pub domain: RaplDomainType,
    /// The event code to use as a "config" field for perf_event_open
    pub code: u8,
    /// should be "Joules"
    pub unit: String,
    /// The scale to apply in order to get joules (`energy_j = count * scale`).
    /// Should be "0x1.0p-32" (thus, f32 is fine)
    pub scale: f32,
}

impl PowerEvent {
    /// Make a system call to [perf_event_open](https://www.man7.org/linux/man-pages/man2/perf_event_open.2.html)
    /// with `attr.config = self.code` and `attr.type = pmu_type`.
    ///
    /// # Arguments
    /// * `pmu_type` - The type of the RAPL PMU, given by [`pmu_type()`].
    /// * `cpu_id` - Defines which CPU (core) to monitor, given by [`super::cpus_to_monitor()`]
    ///
    pub fn perf_event_open(&self, pmu_type: u32, cpu_id: u32) -> std::io::Result<i32> {
        // Only some combination of (pid, cpu) are valid.
        // For RAPL PMU events, we use (-1, cpu) which means "all processes, one cpu".
        let pid = -1; // all processes
        let cpu = cpu_id as i32;

        let mut attr = sys::bindings::perf_event_attr::default();
        attr.config = self.code.into();
        attr.type_ = pmu_type;
        attr.size = core::mem::size_of_val(&attr) as u32;
        debug!("{attr:?}");

        let result = unsafe { sys::perf_event_open(&mut attr, pid, cpu, -1, 0) };
        if result == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }
}

/// Retrieves the type of the RAPL PMU (Power Monitoring Unit) in the Linux kernel.
pub fn pmu_type() -> Result<u32> {
    let path = Path::new("/sys/devices/power/type");
    let read = fs::read_to_string(path).with_context(|| format!("Failed to read {path:?}"))?;
    let typ = read
        .trim_end()
        .parse()
        .with_context(|| format!("Failed to parse {path:?}: '{read}'"))?;
    Ok(typ)
}

/// Retrieves all RAPL power events exposed in sysfs.
/// There can be more than just `cores`, `pkg` and `dram`.
/// For instance, there can be `gpu` and
/// [`psys`](https://patchwork.kernel.org/project/linux-pm/patch/1458253409-13318-1-git-send-email-srinivas.pandruvada@linux.intel.com/).
pub fn all_power_events() -> Result<Vec<PowerEvent>> {
    let mut events: Vec<PowerEvent> = Vec::new();

    fn read_event_code(path: &Path) -> Result<u8> {
        let read = fs::read_to_string(path)?;
        let code_str = read
            .trim_end()
            .strip_prefix("event=0x")
            .with_context(|| format!("Failed to strip {path:?}: '{read}'"))?;
        let code = u8::from_str_radix(code_str, 16).with_context(|| format!("Failed to parse {path:?}: '{read}'"))?; // hexadecimal
        Ok(code)
    }

    fn read_event_unit(main: &Path) -> Result<String> {
        let mut path = main.to_path_buf();
        path.set_extension("unit");
        let unit_str = fs::read_to_string(path)?.trim_end().to_string();
        Ok(unit_str)
    }

    fn read_event_scale(main: &Path) -> Result<f32> {
        let mut path = main.to_path_buf();
        path.set_extension("scale");
        let read = fs::read_to_string(&path)?;
        let scale = read
            .trim_end()
            .parse()
            .with_context(|| format!("Failed to parse {path:?}: '{read}'"))?;
        Ok(scale)
    }

    fn parse_event_name(name: &str) -> Option<RaplDomainType> {
        match name {
            "cores" => Some(RaplDomainType::PP0),
            "gpu" => Some(RaplDomainType::PP1),
            "psys" => Some(RaplDomainType::Platform),
            "pkg" => Some(RaplDomainType::Package),
            "ram" => Some(RaplDomainType::Dram),
            _ => None,
        }
    }

    // Find all the events
    for e in fs::read_dir("/sys/devices/power/events")? {
        let entry = e?;
        let path = entry.path();
        let file_name = path.file_name().unwrap().to_string_lossy();
        // only list the main file, not *.unit nor *.scale
        if path.is_file() && !file_name.contains('.') {
            // The files are named "energy-pkg", "energy-dram", ...
            if let Some(event_name) = file_name.strip_prefix("energy-") {
                // We have the name of the event, we can read all the info
                let name = event_name.to_owned();
                let code = read_event_code(&path)?;
                let unit = read_event_unit(&path)?;
                let scale = read_event_scale(&path)?;
                let domain = parse_event_name(&name).with_context(|| format!("Unknown RAPL perf event {name}"))?;
                events.push(PowerEvent {
                    name,
                    domain,
                    code,
                    unit,
                    scale,
                })
            }
        }
    }
    Ok(events)
}

/// Energy probe based on perf_event for intel RAPL.
pub struct PerfEventProbe {
    /// Stores the energy measurements
    measurements: EnergyMeasurements,

    /// Ready-to-use power events with additional metadata
    events: Vec<OpenedPowerEvent>,
}

struct OpenedPowerEvent {
    fd: File,
    scale: f64,
    socket: u32,
    domain: RaplDomainType,
}

impl PerfEventProbe {
    pub fn new(socket_cpus: &[CpuId], events: &[&PowerEvent]) -> anyhow::Result<PerfEventProbe> {
        crate::check_socket_cpus(socket_cpus)?;
        let pmu_type = pmu_type()?;
        let mut opened = Vec::with_capacity(socket_cpus.len() * events.len());
        for CpuId { cpu, socket } in socket_cpus {
            for event in events {
                let raw_fd = event.perf_event_open(pmu_type, *cpu)?;
                let fd = unsafe { File::from_raw_fd(raw_fd) };
                let scale = event.scale as f64;
                opened.push(OpenedPowerEvent {
                    fd,
                    scale,
                    socket: *socket,
                    domain: event.domain,
                })
            }
        }
        Ok(PerfEventProbe {
            measurements: EnergyMeasurements::new(socket_cpus.len()),
            events: opened,
        })
    }
}

impl EnergyProbe for PerfEventProbe {
    fn poll(&mut self) -> anyhow::Result<()> {
        for evt in &mut self.events {
            let counter_value = read_perf_event(&mut evt.fd)
                .with_context(|| format!("failed to read perf_event {:?} for domain {:?}", evt.fd, evt.domain))?;

            self.measurements
                .push(evt.socket, evt.domain, counter_value, PERF_MAX_ENERGY, evt.scale);
        }
        Ok(())
    }

    fn measurements(&self) -> &crate::EnergyMeasurements {
        &self.measurements
    }
    
    fn reset(&mut self) {
        self.measurements.clear()
    }
}

fn read_perf_event(fd: &mut File) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    // rewind() is INVALID for perf events, we must read "at the cursor" every time
    fd.read(&mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}
