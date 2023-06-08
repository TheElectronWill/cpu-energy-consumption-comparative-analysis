use anyhow::{anyhow, Context};
use clap::Parser;
use rapl_probes::perf_event::PowerEvent;
use rapl_probes::powercap::{PowerZone, PowerZoneHierarchy};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use cli::{Cli, Commands, OutputType, ProbeType};
use log::{debug, info, warn};
use rapl_probes::{
    ebpf,
    msr::{self, RaplVendor},
    perf_event, powercap, EnergyMeasurements, EnergyProbe, RaplDomainType,
};

mod cli;

// A tokio runtime is required for aya ebpf
#[tokio::main(worker_threads = 1)]
async fn main() -> Result<(), anyhow::Error> {
    // initialize logger
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::init_from_env(env);

    // parse CLI arguments
    let cli = Cli::parse();

    // get cpu info, accessible perf events and power zones
    let all_cpus = rapl_probes::online_cpus()?;
    let socket_cpus = rapl_probes::cpus_to_monitor()?;
    let perf_events = rapl_probes::perf_event::all_power_events()?;
    let power_zones = rapl_probes::powercap::all_power_zones()?;

    let n_sockets = socket_cpus.len();
    let n_cpu_cores = all_cpus.len();
    info!("{n_sockets}/{n_cpu_cores} monitorable CPU (cores) found: {socket_cpus:?}");

    // check the consistency of the RAPL interfaces
    let available_domains = check_domains_consistency(&perf_events, &power_zones);

    // run the command
    match cli.command {
        Commands::Info => {
            println!("\nFound RAPL perf events:");
            for evt in &perf_events {
                println!("- {evt:?}");
            }

            println!("\nFound powercap zones:");
            for zone in &power_zones.top {
                println!("{zone}");
            }

            println!("\nAll available RAPL domains: {}", mkstring(&available_domains, ", "));
        }
        Commands::Poll {
            probe,
            domains,
            frequency,
            output,
        } => {
            // filter the domains according to the command-line arguments
            if !domains.iter().all(|d| available_domains.contains(d)) {
                return Err(anyhow!("Invalid selected domains: {}", mkstring(&domains, ", ")));
            }

            let filtered_events: Vec<&PowerEvent> =
                perf_events.iter().filter(|e| domains.contains(&e.domain)).collect();

            // the powercap zones are organized in a hierarchy, we need to explore them recursively
            let filtered_zones: Vec<&PowerZone> = power_zones
                .flat
                .iter()
                .filter(|z| domains.contains(&z.domain))
                .collect();

            // create the RAPL probe
            let mut probe: Box<dyn EnergyProbe> = match probe {
                ProbeType::PowercapSysfs => {
                    let p = powercap::PowercapProbe::<true>::new(&socket_cpus, &filtered_zones)?;
                    Box::new(p)
                }
                ProbeType::PerfEvent => {
                    let p = perf_event::PerfEventProbe::new(&socket_cpus, &filtered_events)?;
                    Box::new(p)
                }
                ProbeType::Ebpf => {
                    let p = ebpf::EbpfProbe::new(&socket_cpus, &filtered_events, frequency)?;
                    Box::new(p)
                }
                ProbeType::Msr => {
                    let p = msr::MsrProbe::new(&socket_cpus, &domains)?;
                    Box::new(p)
                }
            };

            // Query the probe at the given frequency, in another thread
            let polling_period = Duration::from_secs_f64({
                if frequency == 0 {
                    0.0
                } else {
                    1.0 / frequency as f64
                }
            });

            let writer: Option<Box<dyn Write>> = match output {
                OutputType::None => None,
                OutputType::Stdout => Some(Box::new(std::io::stdout())),
                OutputType::File => {
                    // create the csv file
                    let filename = OffsetDateTime::now_utc().format(&Rfc3339)?;
                    let file = File::create(filename)?;
                    let writer = BufWriter::new(file);
                    // return the writer
                    Some(Box::new(writer))
                }
            };

            // Poll the probe (if any) at regular intervals
            poll_energy_probe(probe.as_mut(), polling_period, writer)
                .await
                .expect("probe error");
        }
    }

    Ok(())
}

async fn poll_energy_probe(
    probe: &mut dyn EnergyProbe,
    period: Duration,
    mut writer: Option<Box<dyn Write>>,
) -> anyhow::Result<()> {
    // write the csv header
    if let Some(w) = &mut writer {
        w.write("socket;domain;overflow;joules\n".as_bytes())?;
    }

    loop {
        // sleep before the first measurement, because the eBPF program has probably
        // not been triggered by the clock event yet
        tokio::time::sleep(period).await;

        // poll the new values from the probe
        probe.poll().context("refreshing measurements")?;
        let measurements = probe.measurements();

        // (optional) print values
        if let Some(w) = &mut writer {
            print_measurements(measurements, w).context("printing measurements")?;
        }

        // prevent the compiler from removing the measurement
        std::hint::black_box(measurements);
    }
}

fn print_measurements(m: &EnergyMeasurements, writer: &mut dyn Write) -> anyhow::Result<()> {
    for (socket_id, domains_of_socket) in m.per_socket.iter().enumerate() {
        for (domain, counter) in domains_of_socket {
            if let Some(consumed) = counter.joules {
                let overflow = counter.overflowed;
                writer.write(format!("{socket_id};{domain:?};{overflow};{consumed}\n").as_bytes())?;
            }
        }
    }
    Ok(())
}

fn check_domains_consistency(perf_events: &[PowerEvent], power_zones: &PowerZoneHierarchy) -> Vec<RaplDomainType> {
    // get all the domains available via perf-events
    let mut perf_rapl_domains: Vec<RaplDomainType> = perf_events.iter().map(|e| e.domain).collect();
    perf_rapl_domains.sort_by_key(|k| k.to_string());

    // get all the domains available via Powercap
    let mut powercap_rapl_domains: Vec<RaplDomainType> = power_zones.flat.iter().map(|z| z.domain).collect();
    powercap_rapl_domains.sort_by_key(|k| k.to_string());

    if perf_rapl_domains != powercap_rapl_domains {
        warn!("Powercap and perf-event don't report the same RAPL domains. This may be due to a bug in powercap or in perf-event.");
        warn!("Upgrading to a newer kernel could fix the problem.");
        warn!("Perf-event: {}", mkstring(&perf_rapl_domains, ", "));
        warn!("Powercap:   {}", mkstring(&powercap_rapl_domains, ", "));

        if rapl_probes::msr::cpu_vendor().unwrap() == RaplVendor::Amd {
            warn!(
                "AMD cpus only supports the \"pkg\" domain (and sometimes \"core\"), but their support is buggy on old Linux kernels!

                - All events are present in the sysfs, but they should not be there. This seems to have been fixed in Linux 5.17.
                See https://github.com/torvalds/linux/commit/0036fb00a756a2f6e360d44e2e3d2200a8afbc9b.

                - The \"core\" domain doesn't work in perf-event, it could be added soon, if it's supported.
                See https://lore.kernel.org/lkml/20230217161354.129442-1-wyes.karny@amd.com/T/.

                NOTE: It could also be totally unsupported, because it gives erroneous/aberrant values in powercap on our bi-socket AMD EPYC 7702 64-core Processor.
                "
            );
        }
    } else {
        info!("Available RAPL domains: {}", mkstring(&perf_rapl_domains, ", "));
    }

    if perf_rapl_domains.len() >= powercap_rapl_domains.len() {
        perf_rapl_domains
    } else {
        powercap_rapl_domains
    }
}

/// Takes a slice of elements that can be converted to strings, converts them and joins them all.
fn mkstring<A: ToString>(elems: &[A], sep: &str) -> String {
    elems.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(sep)
}
