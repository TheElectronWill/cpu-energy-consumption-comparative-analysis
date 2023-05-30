use std::{fs, num::ParseIntError};

use clap::ValueEnum;
use enum_map::{self, Enum, EnumMap};

#[cfg(feature = "ebpf")]
pub mod ebpf;

pub mod msr;
pub mod perf_event;
pub mod powercap;

#[derive(Enum, Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RaplDomainType {
    /// entire socket
    Package,
    /// power plane 0: core
    PP0,
    /// power plane 1: uncore
    PP1,
    ///  DRAM
    Dram,
    /// psys
    Platform,
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
    /// Returns the number of Joules consumed since the last call, per domain,
    /// based on the underlying energy counters, and a flag that indicates
    /// whether an overflow has occured (`true` means overflow, `false` means no overflow).
    ///
    /// If this is the first call, returns `None`.
    ///
    /// ## Usage
    ///
    /// ```
    /// // Retrieve the first CPU of each socket (the others won't work)
    /// let socket_cpus = perf_rapl::cpus_to_monitor();
    ///
    /// // Init the measurements container.
    /// let measurements = EnergyMeasurements::new(socket_cpus.len());
    ///
    /// // Init the energy probe (perf_event/msr/etc.), it will retrieve the RAPL counters
    /// let probe = todo!("rapl_way::Probe::new(...)");
    ///
    /// // Measure in loop
    /// loop {
    ///     for (s, _) in socket_cpus.enumerate() {
    ///         for (rapl_domain, counter) in measurements.domains_of_socket(s) {
    ///             if let Some(consumed) = counter.joules {
    ///                 println!("socket {s}, domain {rapl_domain}: {consumed} Joules")
    ///             }
    ///         }
    ///     }
    ///     std::thread::sleep(Duration::from_secs(1));
    ///       
    /// }
    /// if let Some((joules, overflow)) = probe.read_consumed_joules() {
    ///     println!("{joules} J consumed");
    /// }
    ///
    /// ```
    ///
    /// ## Overflows
    ///
    /// RAPL counters overflow after some time, which depends on the consumption
    /// of the monitored domain. This time can be lower than one minute.
    /// To avoid losing data and reporting wrong measurements, no more than one overflow
    /// must occur between two measurements. That is, the polling frequency must be high enough.
    ///
    /// If two consecutive calls return `true`, then the frequency is either too low,
    /// or barely right (but that's risky).
    ///
    fn read_consumed_energy(&mut self, to: &mut EnergyMeasurements) -> anyhow::Result<()>;
}

pub struct EnergyMeasurements {
    pub per_socket: Vec<EnumMap<RaplDomainType, EnergyCounter>>,
}

#[derive(Default, Clone)]
pub struct EnergyCounter {
    /// The previous, raw value of the RAPL counter. The energy unit has not been applied yet.
    previous_value: Option<u64>,

    /// `true` if an overflow has occured in the last call of `read_consumed_energy`.
    pub overflowed: bool,

    // NOTE: the energy can be a floating-point number in Joules,
    // without any loss of precision. Why? Because multiplying any number
    // by a float that is a power of two will only change the "exponent" part,
    // not the "mantissa", and the energy unit for RAPL is always a power of two.
    //
    // A f32 can hold integers without any precision loss
    // up to approximately 2^24, which is not enough for the RAPL counter values,
    // so we use a f64 here.
    /// The energy consumed since the previous call to `read_consumed_energy`, in Joules.
    pub joules: Option<f64>,
}

impl EnergyMeasurements {
    pub fn new(socket_count: usize) -> EnergyMeasurements {
        let v = vec![EnumMap::default(); socket_count];
        EnergyMeasurements { per_socket: v }
    }

    pub fn domains_of_socket(&self, socket_id: u32) -> impl Iterator<Item = (RaplDomainType, &EnergyCounter)> {
        self.per_socket[socket_id as usize].iter()
    }

    pub fn push(&mut self, socket_id: u32, domain: RaplDomainType, counter_value: u64, energy_unit: f64) {
        let current = counter_value;
        let counter = &mut self.per_socket[socket_id as usize][domain];
        if let Some(prev) = counter.previous_value {
            if current < prev {
                // one or more overflow have occured, we cannot know how many,
                // so we correct only one.
                let corrected = u64::MAX - prev + current;
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

#[cfg(feature = "ebpf")]
pub fn online_cpus() -> anyhow::Result<Vec<u32>> {
    let list = fs::read_to_string("/sys/devices/system/cpu/online")?;
    parse_cpu_list(&list)
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
