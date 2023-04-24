use anyhow::{Context, Result};
use aya::programs::PerfEventScope;
use log::debug;
use perf_event_open_sys as sys;
use std::{
    fs::{self, File},
    io::Read,
    num::ParseIntError,
    os::fd::{FromRawFd, self},
    path::Path,
};

use super::EnergyMeasurement;

// See https://github.com/torvalds/linux/commit/4788e5b4b2338f85fa42a712a182d8afd65d7c58
// for an explaination of the RAPL PMU driver.

#[derive(Debug)]
pub struct PowerEvent {
    /// The name of the power event. This corresponds to a RAPL **domain name**, like "pkg".
    pub name: String,
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
    /// * `scope` - Defines which process and CPU to monitor
    ///
    pub fn perf_event_open(&self, pmu_type: u32, scope: PerfEventScope) -> std::io::Result<i32> {
        // Only some combination of (pid, cpu) are valid.
        // PerfEventScope always represents a valid combination, to avoid errors.
        let (pid, cpu) = match scope {
            PerfEventScope::CallingProcessAnyCpu => (0, -1),
            PerfEventScope::CallingProcessOneCpu { cpu } => (0, cpu as i32),
            PerfEventScope::OneProcessAnyCpu { pid } => (pid as i32, -1),
            PerfEventScope::OneProcessOneCpu { cpu, pid } => (pid as i32, cpu as i32),
            PerfEventScope::AllProcessesOneCpu { cpu } => (-1, cpu as i32),
        };

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

/// Retrieves the CPUs to monitor (one per socket) in order
/// to get RAPL perf counters.
pub fn cpus_to_monitor() -> Result<Vec<u32>> {
    let mask = fs::read_to_string("/sys/devices/power/cpumask")?;
    let res = mask
        .trim_end()
        .split(',')
        .map(str::parse)
        .collect::<Result<Vec<u32>, ParseIntError>>()?;
    Ok(res)
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

    // Find all the events
    for e in fs::read_dir("/sys/devices/power/events")? {
        let entry = e?;
        let path = entry.path();
        let file_name = path.file_name().unwrap().to_string_lossy();
        // only list the main file, not *.unit nor *.scale
        if path.is_file() && !file_name.contains('.') {
            if let Some(event_name) = file_name.strip_prefix("energy-") {
                // We have the name of the event, we can read all the info
                let code = read_event_code(&path)?;
                let unit = read_event_unit(&path)?;
                let scale = read_event_scale(&path)?;
                events.push(PowerEvent {
                    name: event_name.to_owned(),
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
    opened: Vec<OpenedPowerEvent>,
}

struct OpenedPowerEvent {
    file: File,
    scale: f64,
    cpu: u32,
}

impl PerfEventProbe {
    pub fn new(socket_cpus: &Vec<u32>, event: &PowerEvent) -> anyhow::Result<PerfEventProbe> {
        let pmu_type = pmu_type()?;
        let mut opened = Vec::with_capacity(socket_cpus.len());
        for cpu in socket_cpus {
            let fd = event.perf_event_open(
                pmu_type,
                aya::programs::PerfEventScope::AllProcessesOneCpu { cpu: *cpu },
            )?;
            let file = unsafe { File::from_raw_fd(fd) };
            let scale = event.scale as f64;
            opened.push(OpenedPowerEvent { file, scale, cpu: *cpu })
        }
        Ok(PerfEventProbe { opened })
    }
}

impl super::Probe for PerfEventProbe {
    fn read_uj(&mut self, out: &mut Vec<EnergyMeasurement>) -> anyhow::Result<()> {
        let mut buf = [0u8; 8];

        for evt in &mut self.opened {
            // evt.file.rewind()?; INVALID for perf events, and useless
            evt.file.read(&mut buf)?;
            let raw = u64::from_ne_bytes(buf);
            let joules = (raw as f64) * evt.scale;
            let u_joules = (joules * 1000_000.0) as u64; // Joules to microJoules
            out.push(EnergyMeasurement {
                energy_counter: u_joules,
                cpu: evt.cpu,
            })
        }
        Ok(())
    }
}