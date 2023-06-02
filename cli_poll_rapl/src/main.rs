use std::{fmt::Display, time::Duration};

use clap::{Parser, ValueEnum};
use log::{debug, info, warn};
use rapl_probes::{
    ebpf,
    msr::{self, RaplVendor},
    perf_event, powercap, EnergyMeasurements, EnergyProbe, RaplDomainType,
};

mod bench;

#[derive(Parser)]
#[command(author, version)]
struct Cli {
    /// How to access RAPL counters.
    #[arg(value_enum)]
    probe: ProbeType,

    /// The RAPL domains to record.
    #[arg(short, long, value_delimiter = ',')]
    domains: Vec<RaplDomainType>,

    /// Measurement frequency, in Hertz.
    #[arg(short, long)]
    frequency: u64,

    /// Only show info about CPU and RAPL domains, then exit.
    #[arg(long, default_value_t = false)]
    info: bool,

    /// Print energy measurements on each iteration.
    #[arg(short, long, default_value_t = OutputType::None)]
    output: OutputType,
}

#[derive(Clone, ValueEnum, Debug, PartialEq, Eq)]
enum OutputType {
    None,
    Stdout,
    Csv,
}

impl Display for OutputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (self as &dyn std::fmt::Debug).fmt(f)
    }
}

#[derive(Clone, ValueEnum, Debug, PartialEq, Eq)]
enum ProbeType {
    PowercapSysfs,
    PerfEvent,
    Ebpf,
    Msr,
}

impl Display for ProbeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ProbeType::PowercapSysfs => "powercap-sysfs",
            ProbeType::PerfEvent => "perf-event",
            ProbeType::Ebpf => "ebpf",
            ProbeType::Msr => "msr",
        };
        f.write_str(str)
    }
}

// A tokio runtime is required for aya ebpf
#[tokio::main(worker_threads = 1)]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let cli = Cli::parse();

    let all_cpus = rapl_probes::online_cpus()?;
    let socket_cpus = rapl_probes::cpus_to_monitor()?;
    let perf_events = rapl_probes::perf_event::all_power_events()?;
    let power_zones = rapl_probes::powercap::all_power_zones()?;
    let cpu_vendor = rapl_probes::msr::cpu_vendor()?;

    let n_sock = socket_cpus.len();
    let n_all_cores = all_cpus.len();
    info!("{n_sock}/{n_all_cores} monitorable CPU (cores) found: {socket_cpus:?}");

    info!("Found RAPL perf events:");
    for evt in &perf_events {
        info!("- {evt:?}");
    }

    info!("Found powercap zones:");
    for zone in &power_zones {
        info!("{zone}");
    }

    if cpu_vendor == RaplVendor::Amd {
        warn!(
            "AMD cpus only supports the \"pkg\" and \"core\" domains, bug their support is buggy on old Linux kernels!:
            - All events are present in the sysfs, but they should not be there
            see https://github.com/torvalds/linux/commit/0036fb00a756a2f6e360d44e2e3d2200a8afbc9b.
            - The \"core\" domain doesn't work in perf-event, it has been added recently.
            https://lore.kernel.org/lkml/20230217161354.129442-1-wyes.karny@amd.com/T/
            
            Also, the \"core\" domain, in powercap, gives erroneous/useless values on our bi-socket AMD machine.
            "
        );
    }

    if cli.info {
        return Ok(());
    }

    // create the RAPL probe
    let probe: Box<dyn EnergyProbe> = match cli.probe {
        ProbeType::PowercapSysfs => {
            let zones: Vec<&powercap::PowerZone> =
                power_zones.iter().filter(|z| cli.domains.contains(&z.domain)).collect();
            let p = powercap::PowercapProbe::<true>::new(&zones)?;
            Box::new(p)
        }
        ProbeType::PerfEvent => {
            let events: Vec<&perf_event::PowerEvent> =
                perf_events.iter().filter(|e| cli.domains.contains(&e.domain)).collect();
            let p = perf_event::PerfEventProbe::new(&socket_cpus, &events)?;
            Box::new(p)
        }
        ProbeType::Ebpf => {
            let events: Vec<&perf_event::PowerEvent> =
                perf_events.iter().filter(|e| cli.domains.contains(&e.domain)).collect();
            let p = ebpf::EbpfProbe::new(&socket_cpus, &events, cli.frequency)?;
            Box::new(p)
        }
        ProbeType::Msr => {
            let p = msr::MsrProbe::new(&socket_cpus, &cli.domains)?;
            Box::new(p)
        }
    };

    // Query the probe at the given frequency, in another thread
    let polling_period = Duration::from_secs_f64({
        if cli.frequency == 0 {
            0.0
        } else {
            1.0 / cli.frequency as f64
        }
    });

    // A holder for the measurements
    let mut m = EnergyMeasurements::new(n_sock);

    // Poll the probe (if any) at regular intervals
    poll_energy_probe(probe.as_mut(), polling_period, &mut m, cli.output)
        .await
        .expect("probe error");

    Ok(())
}

async fn poll_energy_probe(
    probe: &mut dyn EnergyProbe,
    period: Duration,
    m: &mut EnergyMeasurements,
    output: OutputType,
) -> anyhow::Result<()> {
    loop {
        // sleep before the first measurement, because the eBPF program has probably
        // not been triggered by the clock event yet
        tokio::time::sleep(period).await;

        // poll the new values from the probe
        probe.read_consumed_energy(m)?;

        // (optional) print values
        if print {
            print_measurements(&m);
        }

        // prevent the compiler from removing the measurement
        std::hint::black_box(&m);
    }
}

fn print_measurements(m: &EnergyMeasurements) {
    for (socket_id, domains_of_socket) in m.per_socket.iter().enumerate() {
        for (domain, counter) in domains_of_socket {
            if let Some(consumed) = counter.joules {
                let overflow = counter.overflowed;
                println!("*socket={socket_id};domain={domain:?};overflow={overflow};consumed_joules={consumed}");
            }
        }
    }
}
