use std::{
    process::Command,
    time::Duration,
};

use anyhow::Context;
use aya::util::online_cpus;
use clap::{Parser, ValueEnum};
use log::debug;
use userspace::probes::{ebpf, perf_rapl, powercap, Probe};

#[derive(Parser)]
#[command(author, version)]
struct Cli {
    #[arg(value_enum)]
    probe: ProbeType,

    /// Measurement frequency, in Hertz
    #[arg(short, long)]
    frequency: u64,

    /// Number of sysbench "events" to compute.
    #[arg(short, long)]
    n_events: u64,
}

#[derive(Clone, ValueEnum)]
enum ProbeType {
    PowercapSysfs,
    PerfEvent,
    Ebpf,
    None,
}

// A tokio runtime is required for aya ebpf
#[tokio::main(worker_threads = 1)]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let cli = Cli::parse();

    let rapl_events = perf_rapl::all_power_events()?;
    let socket_cpus = perf_rapl::cpus_to_monitor()?;
    let power_zones = powercap::all_power_zones()?;

    for evt in &rapl_events {
        println!("Found RAPL perf_event {evt:?}");
    }
    println!("Found powercap zones:");
    for zone in &power_zones {
        println!("{zone}");
    }
    let n = socket_cpus.len();
    println!("{n} monitorable CPU (cores) found: {socket_cpus:?}");

    let probe: Option<Box<dyn Probe>> = match cli.probe {
        ProbeType::PowercapSysfs => {
            let zone_pkg = power_zones
                .iter()
                .find(|z| z.name == "package-0")
                .context("no pkg powercap zone")?;
            let z0 = vec![(zone_pkg, 0u32)];
            Some(Box::new(powercap::PowercapProbe::new(&z0)?))
        }
        ProbeType::PerfEvent => {
            // Call perf_event_open for each event and each cpu, and populate the array with the file descriptors
            // NB: the AMD node we have only supports the "pkg" domain event, so we only use this one.
            // A bug in the Linux kernel makes all events available in the sysfs (so in our `rapl_events`),
            // see https://github.com/torvalds/linux/commit/0036fb00a756a2f6e360d44e2e3d2200a8afbc9b.
            let pkg_event = rapl_events.iter().find(|e| e.name == "pkg").context("no pkg event")?;
            Some(Box::new(perf_rapl::PerfEventProbe::new(&socket_cpus, pkg_event)?))
        }
        ProbeType::Ebpf => {
            let pkg_event = rapl_events.iter().find(|e| e.name == "pkg").context("no pkg event")?;
            Some(Box::new(ebpf::EbpfProbe::new(&socket_cpus, pkg_event, cli.frequency)?))
        }
        ProbeType::None => None,
    };

    // Query the probe at the given frequency, in another thread
    if let Some(p) = probe {
        tokio::spawn(async move {
            poll_energy_probe(p, cli.frequency as f64).expect("probe error");
        });
    }

    // start a big computation with sysbench
    std::thread::sleep(Duration::from_secs(10));
    //run_cpu_benchmark(50_000)?;

    // Exit and stop the polling.
    std::process::exit(0);
    // Ok(())
}

fn poll_energy_probe(mut probe: Box<dyn Probe>, frequency: f64) -> anyhow::Result<()> {
    let period = 1.0 / frequency;
    let dur = Duration::from_secs_f64(period);
    let mut previous: Option<u64> = None;
    loop {
        // sleep before the first measurement, because the eBPF program has probably
        // not been triggered by the clock event yet
        std::thread::sleep(dur);

        let measurements = probe.read_uj()?;
        debug!("Got {measurements:?} uj");
        let current = measurements.first().unwrap().energy_counter;
        if let Some(prev) = previous {
            let diff = current-prev;
            // todo handle overflow
            let diff_j = (diff as f64) / 1000_000.0;
            debug!("Consumed since last time: {diff_j} Joules")
        }
        previous = Some(current);
    }
}

fn run_cpu_benchmark(n_events: usize) -> anyhow::Result<()> {
    // It seems more precise to limit the number of events instead of the running time.
    // The goal "number of events" seems to be always reached perfectly, but the running time slightly varies.
    let n_cores = online_cpus()?.len();
    let child = Command::new("sysbench")
        .args([
            "cpu",
            "run",
            &format!("--events={n_events}"),
            &format!("--threads={n_cores}"),
        ])
        .spawn()?;
    let out = child.wait_with_output()?;
    let stdout = std::str::from_utf8(&out.stdout)?;
    println!("{stdout}");
    Ok(())
}
