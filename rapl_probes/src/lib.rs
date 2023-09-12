use std::{collections::HashSet, fmt, fs, num::ParseIntError, str::FromStr};

use enum_map::{self, EnumMap};

#[cfg(feature = "ebpf")]
pub mod ebpf;

pub mod msr;
pub mod perf_event;
pub mod powercap;

/// A known RAPL domain.
#[derive(enum_map::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaplDomainType {
    /// entire socket
    Package,
    /// power plane 0: core
    PP0,
    /// power plane 1: uncore
    PP1,
    ///  DRAM
    Dram,
    /// psys (only available on recent client platforms like laptops)
    Platform,
}

impl fmt::Display for RaplDomainType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl FromStr for RaplDomainType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "package" | "pkg" => Ok(RaplDomainType::Package),
            "pp0" | "core" => Ok(RaplDomainType::PP0),
            "pp1" | "uncore" => Ok(RaplDomainType::PP1),
            "dram" | "ram" => Ok(RaplDomainType::Dram),
            "platform" | "psys" => Ok(RaplDomainType::Platform),
            _ => Err(s.to_owned()),
        }
    }
}

impl RaplDomainType {
    pub const ALL: [RaplDomainType; 5] = [
        RaplDomainType::Package,
        RaplDomainType::PP0,
        RaplDomainType::PP1,
        RaplDomainType::Dram,
        RaplDomainType::Platform,
    ];

    pub const ALL_IN_ADDR_ORDER: [RaplDomainType; 5] = [
        RaplDomainType::Package,
        RaplDomainType::Dram,
        RaplDomainType::PP0,
        RaplDomainType::PP1,
        RaplDomainType::Platform,
    ];
}

pub trait EnergyProbe: Send {
    /// Updates the energy measurements.
    fn poll(&mut self) -> anyhow::Result<()>;

    /// Retrieves the latest measurements.
    fn measurements(&self) -> &EnergyMeasurements;
    
    /// Resets the measurements.
    fn reset(&mut self);
}

#[derive(Clone, Debug)]
pub struct EnergyMeasurements {
    pub per_socket: Vec<EnumMap<RaplDomainType, EnergyCounter>>,
}

#[derive(Default, Clone, Debug)]
pub struct EnergyCounter {
    /// The previous, raw value of the counter (its range depends on the RAPL probe).
    /// The energy unit has not been applied yet.
    pub(crate) previous_value: Option<u64>,

    /// `true` if an overflow has occured in the last call of `read_consumed_energy`.
    pub overflowed: bool,

    /// The energy consumed since the previous call to [EnergyProbe::poll], in Joules.
    pub joules: Option<f64>,
    // NOTE: the energy can be a floating-point number in Joules,
    // without any loss of precision. Why? Because multiplying any number
    // by a float that is a power of two will only change the "exponent" part,
    // not the "mantissa", and the energy unit for RAPL is always a power of two.
    //
    // A f32 can hold integers without any precision loss
    // up to approximately 2^24, which is not enough for the RAPL counter values,
    // so we use a f64 here.
}

impl EnergyMeasurements {
    pub fn new(socket_count: usize) -> EnergyMeasurements {
        let v = vec![EnumMap::default(); socket_count];
        EnergyMeasurements { per_socket: v }
    }
    
    pub fn clear(&mut self) {
        for m in &mut self.per_socket {
            m.clear();
        }
    }

    pub fn push(
        &mut self,
        socket_id: u32,
        domain: RaplDomainType,
        counter_value: u64,
        max_value: u64,
        energy_unit: f64,
    ) {
        let current = counter_value;
        let counter = &mut self.per_socket[socket_id as usize][domain];
        if let Some(prev) = counter.previous_value {
            if current < prev {
                // one or more overflow have occured, we cannot know how many, so we correct only one.
                let corrected = max_value - prev + current;
                counter.overflowed = true;
                counter.joules = Some(corrected as f64 * energy_unit)
            } else {
                let diff = current - prev;
                counter.overflowed = false;
                counter.joules = Some(diff as f64 * energy_unit)
            }
        }
        counter.previous_value = Some(current);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuId {
    pub cpu: u32,
    pub socket: u32,
}

/// Retrieves the CPUs to monitor (one per socket) in order
/// to get RAPL perf counters.
pub fn cpus_to_monitor() -> anyhow::Result<Vec<CpuId>> {
    let mask = fs::read_to_string("/sys/devices/power/cpumask")?;
    let cpus_and_sockets = parse_cpu_and_socket_list(&mask)?;
    Ok(cpus_and_sockets)
}

fn parse_cpu_and_socket_list(cpulist: &str) -> anyhow::Result<Vec<CpuId>> {
    let cpus = parse_cpu_list(cpulist);

    // here we assume that /sys/devices/power/cpumask returns one cpu per socket
    let cpus_and_sockets = cpus?
        .into_iter()
        .enumerate()
        .map(|(i, cpu)| CpuId { cpu, socket: i as u32 })
        .collect();

    Ok(cpus_and_sockets)
}

fn parse_cpu_list(cpulist: &str) -> anyhow::Result<Vec<u32>> {
    // handles "n" or "start-end"
    fn parse_cpulist_item(item: &str) -> anyhow::Result<Vec<u32>> {
        let bounds: Vec<u32> = item
            .split('-')
            .map(str::parse)
            .collect::<Result<Vec<u32>, ParseIntError>>()?;

        match bounds.as_slice() {
            &[start, end] => Ok((start..=end).collect()),
            &[n] => Ok(vec![n]),
            _ => Err(anyhow::anyhow!("invalid cpulist: {}", item)),
        }
    }

    // this can be "0,64" or "0-1" or maybe "0-1,64-66"
    let cpus: Vec<u32> = cpulist
        .trim_end()
        .split(',')
        .map(parse_cpulist_item)
        .collect::<anyhow::Result<Vec<Vec<u32>>>>()?
        .into_iter() // not the same as iter() !
        .flatten()
        .collect();

    Ok(cpus)
}

pub fn online_cpus() -> anyhow::Result<Vec<u32>> {
    let list = fs::read_to_string("/sys/devices/system/cpu/online")?;
    parse_cpu_list(&list)
}

/// Checks that the given slice contains only one CPU per socket.
pub(crate) fn check_socket_cpus(cpus: &[CpuId]) -> anyhow::Result<()> {
    let mut seen_sockets: HashSet<u32> = HashSet::new();
    for cpu_info in cpus {
        let s = cpu_info.socket;
        if !seen_sockets.insert(s) {
            return Err(anyhow::anyhow!(
                "At most one CPU should be given per socket, wrong cpus for socket {}",
                s
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::parse_cpu_and_socket_list;
    use crate::CpuId;

    #[test]
    fn test_parse_cpumask() -> anyhow::Result<()> {
        let single = "0";
        assert_eq!(parse_cpu_and_socket_list(single)?, vec![CpuId { cpu: 0, socket: 0 }]);

        let comma = "0,64";
        assert_eq!(
            parse_cpu_and_socket_list(comma)?,
            vec![CpuId { cpu: 0, socket: 0 }, CpuId { cpu: 64, socket: 1 }]
        );

        let caret = "0-1";
        assert_eq!(
            parse_cpu_and_socket_list(caret)?,
            vec![CpuId { cpu: 0, socket: 0 }, CpuId { cpu: 1, socket: 1 }]
        );

        let combined = "1-3,5-6";
        assert_eq!(
            parse_cpu_and_socket_list(combined)?,
            vec![
                CpuId { cpu: 1, socket: 0 },
                CpuId { cpu: 2, socket: 1 },
                CpuId { cpu: 3, socket: 2 },
                CpuId { cpu: 5, socket: 3 },
                CpuId { cpu: 6, socket: 4 },
            ]
        );

        Ok(())
    }
}
