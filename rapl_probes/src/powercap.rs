// See https://www.kernel.org/doc/html/latest/power/powercap/powercap.html
// for an explanation of the Power Capping framework.

use std::{
    fmt::Display,
    fs::{self, File},
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context};

use crate::{EnergyMeasurements, CpuId};

use super::{EnergyProbe, RaplDomainType};

const POWERCAP_RAPL_PATH: &str = "/sys/devices/virtual/powercap/intel-rapl";
const POWER_ZONE_PREFIX: &str = "intel-rapl";
const POWERCAP_ENERGY_UNIT: f64 = 0.000_001; // 1 microJoules

/// Hierarchy of power zones
pub struct PowerZoneHierarchy {
    /// All the zones in the same Vec.
    pub flat: Vec<PowerZone>,
    /// The top zones. To access their children, use [PowerZone::children].
    pub top: Vec<PowerZone>,
}

/// A power zone.
#[derive(Debug, Clone)]
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

    /// The id of the socket that "contains" this zone, if applicable (psys has no socket)
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
pub fn all_power_zones() -> anyhow::Result<PowerZoneHierarchy> {
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
    fn explore_rec(dir: &Path, parent_socket: Option<u32>, flat: &mut Vec<PowerZone>) -> anyhow::Result<Vec<PowerZone>> {
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
                let children = explore_rec(&path, socket_id, flat)?; // recursively explore
                let zone = PowerZone {
                    name,
                    domain,
                    path,
                    children,
                    socket_id,
                };
                zones.push(zone.clone());
                flat.push(zone);
            }
        }
        zones.sort_by_key(|z| z.path.to_string_lossy().to_string());
        Ok(zones)
    }
    let mut flat = Vec::new();
    let top = explore_rec(Path::new(POWERCAP_RAPL_PATH), None, &mut flat)?;
    Ok(PowerZoneHierarchy { flat, top })
}

/// Powercap probe
pub struct PowercapProbe<const CHECK_UTF8: bool> {
    /// Stores the energy measurements
    measurements: EnergyMeasurements,

    /// Ready-to-use powercap zones with additional metadata
    zones: Vec<OpenedZone>,
}

struct OpenedZone {
    file: File,
    socket: u32,
    domain: RaplDomainType,
    /// The maximum energy value for this zone, as reported by `max_energy_uj`
    max_energy_uj: u64,
}

impl<const CHECK_UTF: bool> PowercapProbe<CHECK_UTF> {
    pub fn new(socket_cpus: &[CpuId], zones: &[&PowerZone]) -> anyhow::Result<PowercapProbe<CHECK_UTF>> {
        if zones.is_empty() {
            return Err(anyhow!("At least one power zone is required for PowercapProbe"))?;
        }
        crate::check_socket_cpus(socket_cpus)?;

        let mut opened = Vec::new();

        for zone in zones {
            let file = File::open(zone.energy_path())
                .with_context(|| format!("open {}", zone.energy_path().to_string_lossy()))?;

            let str_max_energy_uj = fs::read_to_string(zone.max_energy_path())
                .with_context(|| format!("read {}", zone.max_energy_path().to_string_lossy()))?;

            let max_energy_uj = str_max_energy_uj
                .trim_end()
                .parse()
                .with_context(|| format!("parse max_energy_uj: '{str_max_energy_uj}'"))?;

            opened.push(OpenedZone {
                file,
                max_energy_uj,
                socket: zone.socket_id.unwrap_or(0), // put psys in socket 0
                domain: zone.domain,
            })
        }

        Ok(PowercapProbe {
            measurements: EnergyMeasurements::new(socket_cpus.len()),
            zones: opened,
        })
    }
}

impl<const CHECK_UTF: bool> EnergyProbe for PowercapProbe<CHECK_UTF> {
    fn poll(&mut self) -> anyhow::Result<()> {
        // reuse the same buffer for all the zones
        // the size of the content of the file `energy_uj` should never exceed those of `max_energy_uj`,
        // which is 16 bytes on all our test machines
        let mut buf = Vec::with_capacity(16);

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
            let counter_value: u64 = content.trim_end().parse().with_context(|| format!("failed to parse {:?}: '{content}'", zone.file))?;

            // store the value, handle the overflow if there is one
            log::debug!("pushing {}/{} value {counter_value}", zone.socket, zone.domain);

            self.measurements.push(
                zone.socket,
                zone.domain,
                counter_value,
                zone.max_energy_uj, // the maximum energy depends on the zone
                POWERCAP_ENERGY_UNIT,
            );

            // clear the buffer, so that we can fill it again
            buf.clear();
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

#[cfg(test)]
mod tests {
    use super::all_power_zones;

    #[test]
    fn test_powercap() {
        let zones = all_power_zones().expect("failed to get powercap power zones");
        println!("---- Hierarchy ----");
        for z in zones.top {
            println!("{z}");
        }
        println!("---- Flat list ----");
        for z in zones.flat {
            println!("{z}")
        }
    }
}
