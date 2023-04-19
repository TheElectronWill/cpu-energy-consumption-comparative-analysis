// See https://www.kernel.org/doc/html/latest/power/powercap/powercap.html
// for an explanation of the Power Capping framework.

use std::{
    fmt::Display,
    fs::{self, File},
    io::{self, Read, Seek},
    path::{Path, PathBuf},
};

use super::EnergyMeasurement;

const POWERCAP_RAPL_PATH: &str = "/sys/devices/virtual/powercap/intel-rapl";
const POWER_ZONE_PREFIX: &str = "intel-rapl";

/// A power zone.
#[derive(Debug)]
pub struct PowerZone {
    /// The name of the zone, for instance `package-0` or `core`.
    pub name: String,

    /// The path of the zone in sysfs, for instance
    /// `/sys/devices/virtual/powercap/intel-rapl/intel-rapl:0`.
    ///
    /// Note that in the above path, `intel-rapl` is the "control type"
    /// and "intel-rapl:0" is the power zone.
    /// On my machine, that zone is named `package-0`.
    pub path: PathBuf,

    /// The sub-zones (can be empty).
    pub children: Vec<PowerZone>,
}

impl PowerZone {
    pub fn energy_path(&self) -> PathBuf {
        self.path.join("energy_uj")
    }

    pub fn max_energy_path(&self) -> PathBuf {
        self.path.join("max_energy_range_uj")
    }

    fn fmt_rec(&self, f: &mut std::fmt::Formatter<'_>, level: i8) -> std::fmt::Result {
        let mut indent = "  ".repeat(level as _);
        if level > 0 {
            indent.insert(0, '\n');
        }
        write!(f, "{indent}- {} \t: {}", self.name, self.path.to_string_lossy())?;
        for subzone in &self.children {
            subzone.fmt_rec(f, level + 1)?;
        }
        Ok(())
    }
}

impl Display for PowerZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_rec(f, 0)
    }
}

/// Discovers all the RAPL power zones in the powercap sysfs.
pub fn all_power_zones() -> io::Result<Vec<PowerZone>> {
    fn explore(dir: &Path) -> io::Result<Vec<PowerZone>> {
        let mut zones = Vec::new();
        for e in fs::read_dir(dir)? {
            let entry = e?;
            let path = entry.path();
            let file_name = path.file_name().unwrap().to_string_lossy();
            if path.is_dir() && file_name.starts_with(POWER_ZONE_PREFIX) {
                let name_path = path.join("name");
                let name = fs::read_to_string(&name_path)?.trim().to_owned();
                let children = explore(&path)?; // recursively explore
                zones.push(PowerZone { name, path, children });
            }
        }
        zones.sort_by_key(|z| z.path.to_string_lossy().to_string());
        Ok(zones)
    }
    explore(Path::new(POWERCAP_RAPL_PATH))
}

/// Powercap probe
pub struct PowercapProbe {
    zones: Vec<OpenedZone>,
}

struct OpenedZone {
    file: File,
    buf_size_hint: usize,
    cpu: u32,
}

impl PowercapProbe {
    pub fn new(zones: &Vec<(&PowerZone, u32)>) -> anyhow::Result<PowercapProbe> {
        let mut opened = Vec::with_capacity(zones.len());
        for (zone, cpu) in zones {
            let file = File::open(zone.energy_path())?;
            let buf_size_hint = fs::read_to_string(zone.max_energy_path())?.len();
            // the size of the content of `energy_uj` should not exceed those of `max_energy_uj`
            opened.push(OpenedZone {
                file,
                buf_size_hint,
                cpu: *cpu,
            })
        }
        Ok(PowercapProbe { zones: opened })
    }
}

impl super::Probe for PowercapProbe {
    fn read_uj(&mut self, out: &mut Vec<EnergyMeasurement>) -> anyhow::Result<()> {
        for zone in &mut self.zones {
            zone.file.rewind()?;
            let mut buf = Vec::with_capacity(zone.buf_size_hint);
            zone.file.read_to_end(&mut buf)?;

            let energy_counter: u64 = std::str::from_utf8(&buf)?.trim_end().parse()?;
            // TODO try with utf validation disabled ?
            out.push(EnergyMeasurement {
                energy_counter,
                cpu: zone.cpu,
            })
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::all_power_zones;

    #[test]
    fn test_powercap() {
        let zones = all_power_zones().expect("failed to get powercap power zones");
        for z in zones {
            println!("{z}");
        }
    }
}
