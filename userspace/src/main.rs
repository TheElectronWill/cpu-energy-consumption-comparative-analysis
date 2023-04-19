use std::{
    collections::HashMap,
    fmt::Display,
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::Context;
use aya::util::online_cpus;
use clap::{Parser, ValueEnum};
use log::{debug, info};
use regex::Regex;
use userspace::probes::{ebpf, perf_rapl, powercap, EnergyMeasurement, Probe};

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
    n_events: usize,

    /// The type of benchmark, see `sysbench --help`.
    #[arg(short, long)]
    benchmark_type: String,

    /// Number of repetitions to do
    #[arg(short, long)]
    repetitions: u64,
}

#[derive(Clone, ValueEnum, Debug, PartialEq, Eq)]
enum ProbeType {
    PowercapSysfs,
    PerfEvent,
    Ebpf,
    //EbpfAsync,
    None,
}

impl Display for ProbeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ProbeType::PowercapSysfs => "powercap-sysfs",
            ProbeType::PerfEvent => "perf-event",
            ProbeType::Ebpf => "ebpf",
            //ProbeType::EbpfAsync => "ebpf-async",
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

    let rapl_events = perf_rapl::all_power_events()?;
    let socket_cpus = perf_rapl::cpus_to_monitor()?;
    let power_zones = powercap::all_power_zones()?;

    info!("Found RAPL perf events:");
    for evt in &rapl_events {
        info!("- {evt:?}");
    }
    info!("Found powercap zones:");
    for zone in &power_zones {
        info!("{zone}");
    }
    let n = socket_cpus.len();
    info!("{n} monitorable CPU (cores) found: {socket_cpus:?}");

    let probe: Option<Box<dyn Probe>> = match cli.probe {
        ProbeType::PowercapSysfs => {
            let pkg_zones: Vec<(&powercap::PowerZone, u32)> = power_zones
                .iter()
                .filter_map(|z| {
                    if let Some(pkg_id) = z.name.strip_prefix("package-") {
                        Some((z, pkg_id.parse().unwrap()))
                    } else {
                        None
                    }
                })
                .collect();
            Some(Box::new(powercap::PowercapProbe::new(&pkg_zones)?))
        }
        ProbeType::PerfEvent => {
            // Call perf_event_open for each event (here only the "pkg" event) and each cpu, and create a probe.
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
    let polling_period = Duration::from_secs_f64(1.0 / cli.frequency as f64);
    if let Some(p) = probe {
        tokio::task::spawn(async move {
            poll_energy_probe(p, polling_period).await.expect("probe error");
        });
    }

    // wait for the measurement to begin
    tokio::time::sleep(polling_period).await;

    // Run the benchmark several times (without recreating the existing probes)
    let benchmark_type = cli.benchmark_type.clone();
    let benchmark_n_threads = online_cpus()?.len();
    for _ in 0..cli.repetitions {
        // start a big computation with sysbench, on all cores
        // <--- t0
        let result = run_benchmark(&benchmark_type, cli.n_events, benchmark_n_threads)?;
        // <--- t1

        // print a line of CSV
        print_results(&cli, result);
    }

    // Exit and stop the polling.
    std::process::exit(0);
    // Ok(())
}

async fn poll_energy_probe(mut probe: Box<dyn Probe>, period: Duration) -> anyhow::Result<()> {
    let mut previous: HashMap<u32, u64> = HashMap::with_capacity(2);
    let mut measurements: Vec<EnergyMeasurement> = Vec::with_capacity(8);
    loop {
        // sleep before the first measurement, because the eBPF program has probably
        // not been triggered by the clock event yet
        tokio::time::sleep(period).await;

        probe.read_uj(&mut measurements)?;
        debug!("Got {measurements:?} uj");

        for m in &measurements {
            let current = m.energy_counter;
            if let Some(prev) = previous.insert(m.cpu, current) {
                let diff = current - prev;
                let diff_j = (diff as f64) / 1000_000.0;
                std::hint::black_box(diff_j); // don't optimize this away!
                debug!("Consumed since last time: {diff_j} Joules");
            }
        }
        measurements.clear(); // we don't do anything with the measurements, clear them to avoid a leak
    }
}

fn run_benchmark(benchmark_type: &str, n_events: usize, n_cores: usize) -> anyhow::Result<SysbenchResults> {
    // It seems more precise to limit the number of events instead of the running time.
    // The goal "number of events" seems to be always reached perfectly, but the running time slightly varies.
    let seed = 42421;
    let child = Command::new("sysbench")
        .args([
            benchmark_type,
            "run",
            &format!("--events={n_events}"),
            &format!("--threads={n_cores}"),
            &format!("--rand-seed={seed}"), // set a seed to limit the differences between two runs
            "--time=0",                     // disable the time limit
        ])
        .stdout(Stdio::piped())
        .spawn()?;
    let out = child.wait_with_output()?;
    let stdout = std::str::from_utf8(&out.stdout)?;
    debug!("{stdout}");

    Ok(parse_sysbench_output(stdout)?)
}

fn parse_sysbench_output(stdout: &str) -> anyhow::Result<SysbenchResults> {
    let time_re = Regex::new(r"total time:\s+([0-9.]+)s")?;
    let evt_re = Regex::new(r"events per second:\s+([0-9.]+)")?;
    let lat_min = Regex::new(r"min:\s+([0-9.]+)")?;
    let lat_avg = Regex::new(r"avg:\s+([0-9.]+)")?;
    let lat_max = Regex::new(r"max:\s+([0-9.]+)")?;
    let lat_percentile = Regex::new(r"95th percentile:\s+([0-9.]+)")?;
    let lat_sum = Regex::new(r"sum:\s+([0-9.]+)")?;

    fn find_and_parse_float(input: &str, regex: Regex, name: &str) -> anyhow::Result<f32> {
        let captures = regex.captures(input).context(format!("{name} not found"))?;
        let g = captures.get(1).unwrap();
        let parsed = g.as_str().parse().with_context(|| format!("failed to parse{g:?}"))?;
        Ok(parsed)
    }

    let events_per_sec: Option<f32> = if let Some(evt_match) = evt_re.captures(stdout) {
        let g = evt_match.get(1).unwrap();
        let value = g
            .as_str()
            .parse::<f32>()
            .with_context(|| format!("failed to parse events per second {evt_match:?}"))?;
        Some(value)
    } else {
        None
    };

    let total_time = find_and_parse_float(stdout, time_re, "total time")?;
    let latency_min = find_and_parse_float(stdout, lat_min, "latency min")?;
    let latency_max = find_and_parse_float(stdout, lat_max, "latency max")?;
    let latency_avg = find_and_parse_float(stdout, lat_avg, "latency avg")?;
    let latency_percentile = find_and_parse_float(stdout, lat_percentile, "latency percentile")?;
    let latency_sum = find_and_parse_float(stdout, lat_sum, "latency sum")?;

    Ok(SysbenchResults {
        total_time,
        events_per_sec,
        latency_min,
        latency_avg,
        latency_max,
        latency_percentile,
        latency_sum,
    })
}

fn print_results(cli: &Cli, result: SysbenchResults) {
    let bench = &cli.benchmark_type;
    let probe = &cli.probe;
    let freq = &cli.frequency;
    let n_events = &cli.n_events;

    let res_time = result.total_time;
    let res_events_rate = result.events_per_sec.unwrap_or(0.0);
    let latency_min = result.latency_min;
    let latency_avg = result.latency_avg;
    let latency_max = result.latency_max;
    let latency_per = result.latency_percentile;
    let latency_sum = result.latency_sum;

    println!("bench={bench};probe={probe};freq={freq};n_events={n_events};time={res_time};rate={res_events_rate};lat_min={latency_min};lat_avg={latency_avg};lat_max={latency_max};lat_perc={latency_per};lat_sum={latency_sum}");
}

#[derive(Debug)]
struct SysbenchResults {
    /// The total execution time, in seconds
    total_time: f32,

    /// Avg events per second
    events_per_sec: Option<f32>,

    /// Latency info
    latency_min: f32,
    latency_max: f32,
    latency_avg: f32,
    latency_sum: f32,
    latency_percentile: f32,
}

#[cfg(test)]
mod tests {
    use crate::parse_sysbench_output;

    #[test]
    fn test_parse_sysbench() {
        let example = "
    Threads started!

    CPU speed:
        events per second:   228.80

    General statistics:
        total time:                          0.0016s
        total number of events:              1

    Latency (ms):
             min:                                    1.52
             avg:                                    1.52
             max:                                    1.52
             95th percentile:                        1.52
             sum:                                    1.52

    Threads fairness:
        events (avg/stddev):           1.0000/0.00
        execution time (avg/stddev):   0.0015/0.00
";
        let res = parse_sysbench_output(example).unwrap();
        assert_eq!(res.total_time, 0.0016);
        assert_eq!(res.events_per_sec, Some(228.80));

        let not_cpu = "
    Threads started!

    General statistics:
        total time:                          0.0713s
        total number of events:              1000

    Latency (ms):
             min:                                    1.01
             avg:                                    2.02
             max:                                    3.03
             95th percentile:                        4.04
             sum:                                    5.05

    Threads fairness:
        events (avg/stddev):           1.0000/0.00
        execution time (avg/stddev):   0.0015/0.00
";
        let res = parse_sysbench_output(not_cpu).unwrap();
        assert_eq!(res.total_time, 0.0713);
        assert_eq!(res.events_per_sec, None);
        assert_eq!(res.latency_min, 1.01);
        assert_eq!(res.latency_avg, 2.02);
        assert_eq!(res.latency_max, 3.03);
        assert_eq!(res.latency_percentile, 4.04);
        assert_eq!(res.latency_sum, 5.05);
    }
}
