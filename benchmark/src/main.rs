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

    /// Number of sysbench "events" to compute.
    #[arg(short, long)]
    n_events: usize,

    /// The type of benchmark, see `sysbench --help`.
    #[arg(short, long)]
    benchmark_type: String,

    /// Number of repetitions to do.
    #[arg(short, long)]
    repetitions: u64,

    /// Only show info about CPU and RAPL domains, then exit.
    #[arg(long, default_value_t = false)]
    info: bool,

    /// Print energy measurements on each iteration.
    #[arg(short, long, default_value_t = false)]
    print_energy: bool,
}

#[derive(Clone, ValueEnum, Debug, PartialEq, Eq)]
enum ProbeType {
    PowercapSysfs,
    PerfEvent,
    Ebpf,
    Msr,
    None,
}

impl Display for ProbeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ProbeType::PowercapSysfs => "powercap-sysfs",
            ProbeType::PerfEvent => "perf-event",
            ProbeType::Ebpf => "ebpf",
            ProbeType::Msr => "msr",
            ProbeType::None => "none",
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
    let probe: Option<Box<dyn EnergyProbe>> = match cli.probe {
        ProbeType::PowercapSysfs => {
            let zones: Vec<&powercap::PowerZone> =
                power_zones.iter().filter(|z| cli.domains.contains(&z.domain)).collect();
            let p = powercap::PowercapProbe::<true>::new(&zones)?;
            Some(Box::new(p))
        }
        ProbeType::PerfEvent => {
            let events: Vec<&perf_event::PowerEvent> =
                perf_events.iter().filter(|e| cli.domains.contains(&e.domain)).collect();
            let p = perf_event::PerfEventProbe::new(&socket_cpus, &events)?;
            Some(Box::new(p))
        }
        ProbeType::Ebpf => {
            let events: Vec<&perf_event::PowerEvent> =
                perf_events.iter().filter(|e| cli.domains.contains(&e.domain)).collect();
            let p = ebpf::EbpfProbe::new(&socket_cpus, &events, cli.frequency)?;
            Some(Box::new(p))
        }
        ProbeType::Msr => {
            let p = msr::MsrProbe::new(&socket_cpus, &cli.domains)?;
            Some(Box::new(p))
        }
        ProbeType::None => None,
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
    let task = probe.map(|mut p| {
        tokio::task::spawn(async move {
            poll_energy_probe(&mut *p, polling_period, &mut m, cli.print_energy)
                .await
                .expect("probe error");
        })
    });

    // wait for the measurement to begin
    tokio::time::sleep(polling_period).await;

    // Run the benchmark several times (without recreating the existing probes)
    let benchmark_type = cli.benchmark_type.clone();
    for _ in 0..cli.repetitions {
        // start a big computation with sysbench, on all cores
        // <--- t0
        let result = bench::run_benchmark(&benchmark_type, cli.n_events, n_all_cores)?;
        // <--- t1

        // print a line of CSV
        print_results(&cli, result);
    }

    // Exit and stop the polling.
    if let Some(t) = task {
        t.abort();
    }
    std::process::exit(0);
}

async fn poll_energy_probe(
    probe: &mut dyn EnergyProbe,
    period: Duration,
    m: &mut EnergyMeasurements,
    print: bool,
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

fn print_results(cli: &Cli, bench_result: Option<bench::SysbenchResults>) {
    let bench = &cli.benchmark_type;
    let probe = &cli.probe;
    let freq = &cli.frequency;
    let n_events = &cli.n_events;

    if let Some(result) = bench_result {
        let res_time = result.total_time;
        let res_events_rate = result.events_per_sec.unwrap_or(0.0);
        let latency_min = result.latency_min;
        let latency_avg = result.latency_avg;
        let latency_max = result.latency_max;
        let latency_per = result.latency_percentile;
        let latency_sum = result.latency_sum;

        println!("bench={bench};probe={probe};freq={freq};n_events={n_events};time={res_time};rate={res_events_rate};lat_min={latency_min};lat_avg={latency_avg};lat_max={latency_max};lat_perc={latency_per};lat_sum={latency_sum}");
    } else {
        println!("bench={bench};probe={probe};freq={freq};n_events={n_events}")
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
