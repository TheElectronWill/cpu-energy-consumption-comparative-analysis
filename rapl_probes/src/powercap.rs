// See https://www.kernel.org/doc/html/latest/power/powercap/powercap.html
// for an explanation of the Power Capping framework.

use std::{
    fmt::Display,
    fs::{self, File},
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use anyhow::Context;

use super::{EnergyProbe, RaplDomainType};

const POWERCAP_RAPL_PATH: &str = "/sys/devices/virtual/powercap/intel-rapl";
const POWER_ZONE_PREFIX: &str = "intel-rapl";
const POWERCAP_ENERGY_UNIT: f64 = 0.000_001; // 1 microJoules

/// A power zone.
#[derive(Debug)]
pub struct PowerZone {
    /// The name of the zone, as returned by powercap, for instance `package-0` or `core`.
    pub name: String,

    /// The RAPL domain type, as an enum
    pub domain: RaplDomainType,

    /// The path of the zone in sysfs, for instance
    /// `/sys/devices/virtual/powercap/intel-rapl/intel-rapl:0`.
    ///
    /// Note that in the above path, `intel-rapl` is the "control type"
    /// and "intel-rapl:0" is the power zone.
    /// On my machine, that zone is named `package-0`.
    pub path: PathBuf,

    /// The sub-zones (can be empty).
    pub children: Vec<PowerZone>,

    /// The id of the socket that "contains" this zone, if applicable (psys has no zone)
    pub socket_id: Option<u32>,
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

        let powercap_name = &self.name;
        let domain = self.domain;
        let path = self.path.to_string_lossy();

        write!(f, "{indent}- {powercap_name} ({domain:?}) \t\t: {path}")?;
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
pub fn all_power_zones() -> anyhow::Result<Vec<PowerZone>> {
    fn parse_zone_name(name: &str) -> Option<RaplDomainType> {
        match name {
            "psys" => Some(RaplDomainType::Platform),
            "core" => Some(RaplDomainType::PP0),
            "uncore" => Some(RaplDomainType::PP1),
            "dram" => Some(RaplDomainType::Dram),
            _ if name.starts_with("package-") => Some(RaplDomainType::Package),
            _ => None,
        }
    }

    /// Recursively explore a power zone
    fn explore_rec(dir: &Path, parent_socket: Option<u32>) -> anyhow::Result<Vec<PowerZone>> {
        let mut zones = Vec::new();
        for e in fs::read_dir(dir)? {
            let entry = e?;
            let path = entry.path();
            let file_name = path.file_name().unwrap().to_string_lossy();

            if path.is_dir() && file_name.starts_with(POWER_ZONE_PREFIX) {
                let name_path = path.join("name");
                let name = fs::read_to_string(&name_path)?.trim().to_owned();
                let socket_id = {
                    if let Some(parent_id) = parent_socket {
                        Some(parent_id)
                    } else if let Some(id_str) = name.strip_prefix("package-") {
                        let id: u32 = id_str
                            .parse()
                            .with_context(|| format!("Failed to extract package id from '{name}'"))?;
                        Some(id)
                    } else {
                        None
                    }
                };
                let domain = parse_zone_name(&name).with_context(|| format!("Unknown RAPL powercap zone {name}"))?;
                let children = explore_rec(&path, socket_id)?; // recursively explore
                zones.push(PowerZone {
                    name,
                    domain,
                    path,
                    children,
                    socket_id,
                });
            }
        }
        zones.sort_by_key(|z| z.path.to_string_lossy().to_string());
        Ok(zones)
    }
    explore_rec(Path::new(POWERCAP_RAPL_PATH), None)
}

/// Powercap probe
pub struct PowercapProbe<const CHECK_UTF8: bool> {
    zones: Vec<OpenedZone>,
    buf_size_hint: usize,
}

struct OpenedZone {
    file: File,
    buf_size_hint: usize,
    socket: u32,
    domain: RaplDomainType,
}

impl<const CHECK_UTF: bool> PowercapProbe<CHECK_UTF> {
    pub fn new(zones: &[&PowerZone]) -> anyhow::Result<PowercapProbe<CHECK_UTF>> {
        let opened = zones
            .iter()
            .map(|zone| {
                let file = File::open(zone.energy_path())?;
                let buf_size_hint = fs::read_to_string(zone.max_energy_path())?.len();
                // the size of the content of `energy_uj` should not exceed those of `max_energy_uj`

                Ok(OpenedZone {
                    file,
                    buf_size_hint,
                    socket: zone.socket_id.unwrap_or(0),
                    domain: zone.domain,
                })
            })
            .collect::<anyhow::Result<Vec<OpenedZone>>>()?;
        let buf_size_hint = opened.iter().map(|z| z.buf_size_hint).max().unwrap();
        Ok(PowercapProbe {
            zones: opened,
            buf_size_hint,
        })
    }
}

impl<const CHECK_UTF: bool> EnergyProbe for PowercapProbe<CHECK_UTF> {
    fn read_consumed_energy(&mut self, to: &mut super::EnergyMeasurements) -> anyhow::Result<()> {
        // reuse the same buffer for all the zones
        let mut buf = Vec::with_capacity(self.buf_size_hint);

        for zone in &mut self.zones {
            // read the file from the beginning
            zone.file.rewind()?;
            zone.file.read_to_end(&mut buf)?;

            // parse the content of the file
            let content = if CHECK_UTF {
                std::str::from_utf8(&buf)?
            } else {
                unsafe { std::str::from_utf8_unchecked(&buf) }
            };
            let counter_value: u64 = content.trim_end().parse()?;
            
            // NOTE: Powercap returns the value of the MSR modified in the following way:
            // TODO explain the computation
            // See: https://github.com/torvalds/linux/blob/9e87b63ed37e202c77aa17d4112da6ae0c7c097c/drivers/powercap/intel_rapl_common.c#L167
            
            // store the value
            to.push(zone.socket, zone.domain, counter_value, POWERCAP_ENERGY_UNIT);
            
            // clear the buffer, so that we can fill it again
            buf.clear();   
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
