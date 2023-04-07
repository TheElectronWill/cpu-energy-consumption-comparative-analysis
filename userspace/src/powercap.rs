
// See https://www.kernel.org/doc/html/latest/power/powercap/powercap.html
// for an explanation of the Power Capping framework.

use std::{path::{PathBuf, Path}, fs, io, fmt::Display};

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
    
    fn fmt_rec(&self, f: &mut std::fmt::Formatter<'_>, level: i8) -> std::fmt::Result {
        let mut indent = "  ".repeat(level as _);
        if level > 0 {
            indent.insert(0, '\n');
        }
        write!(f, "{indent}- {} \t: {}", self.name, self.path.to_string_lossy())?;
        for subzone in &self.children {
            subzone.fmt_rec(f, level+1)?;
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
pub fn find_power_zones() -> io::Result<Vec<PowerZone>> {
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

#[cfg(test)]
mod tests {
    use super::find_power_zones;

    #[test]
    fn test_powercap() {
        let zones = find_power_zones().expect("failed to get powercap power zones");
        for z in zones {
            println!("{z}");
        }
    }
}
