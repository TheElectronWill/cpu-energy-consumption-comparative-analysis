use rapl_probes::perf_event::PowerEvent;
use rapl_probes::powercap::{PowerZone, PowerZoneHierarchy};

use anyhow::anyhow;
use clap::Parser;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use cli::{Cli, Commands, OutputType, ProbeType};
use log::{info, warn};
#[cfg(feature = "enable_ebpf")]
use rapl_probes::ebpf;
use rapl_probes::{
    msr::{self, RaplVendor},
    perf_event, powercap, EnergyProbe, RaplDomainType,
};

mod cli;
mod main_optimized;
#[cfg(any(feature = "bad_sleep", feature = "bad_sleep_singlethread"))]
mod main_bad;

const MEASUREMENTS_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const WRITER_BUFFER_CAPACITY: usize = 8192 * 10;

// A tokio runtime is required for aya ebpf
#[tokio::main(worker_threads = 2)]
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
            output_file,
        } => {
            // compute the polling period, or stop if zero
            let polling_period = Duration::from_secs_f64({
                if frequency == 0.0 {
                    info!("Frequency set to zero, stopping here.");
                    return Ok(());
                } else if frequency < 0.0 {
                    info!("Negative frequency, which means continuous polling.");
                    0.0 // continuous polling
                } else {
                    1.0 / frequency
                }
            });

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
            let probe: Box<dyn EnergyProbe> = match probe {
                ProbeType::PowercapSysfs => {
                    let p = powercap::PowercapProbe::<true>::new(&socket_cpus, &filtered_zones)?;
                    Box::new(p)
                }
                ProbeType::PerfEvent => {
                    let p = perf_event::PerfEventProbe::new(&socket_cpus, &filtered_events)?;
                    Box::new(p)
                }
                ProbeType::Ebpf => {
                    #[cfg(feature = "enable_ebpf")]
                    {
                    let p = ebpf::EbpfProbe::new(&socket_cpus, &filtered_events, frequency as u64)?;
                    Box::new(p)
                    }
                    #[cfg(not(feature = "enable_ebpf"))]
                    {
                        panic!("Invalid probe type 'ebpf': the ebpf feature has not been enabled during the compilation of the tool. Recompile with `--features enable_ebpf` to enable.")
                    }
                }
                ProbeType::Msr => {
                    let p = msr::MsrProbe::new(&socket_cpus, &domains)?;
                    Box::new(p)
                }
            };

            // prepare the output, if any
            let writer: Box<dyn Write + Send> = match output {
                OutputType::None => Box::new(std::io::sink()),
                OutputType::Stdout => Box::new(BufWriter::with_capacity(WRITER_BUFFER_CAPACITY, std::io::stdout())),
                OutputType::File => {
                    let filename = if let Some(f) = output_file {
                        f
                    } else {
                        // create the csv file
                        let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
                        format!("poll-{now}.csv")
                    };
                    let file = File::create(filename)?;
                    let writer = BufWriter::with_capacity(WRITER_BUFFER_CAPACITY, file);
                    // return the writer
                    Box::new(writer)
                }
            };

            #[cfg(not(any(feature = "bad_sleep", feature = "bad_sleep_singlethread")))]
            main_optimized::run(writer, probe, polling_period, MEASUREMENTS_FLUSH_INTERVAL).await?;

            #[cfg(feature = "bad_sleep")]
            main_bad::run_bad_sleep(writer, probe, polling_period, MEASUREMENTS_FLUSH_INTERVAL).await?;

            #[cfg(feature = "bad_sleep_singlethread")]
            main_bad::run_bad_sleep_singlethread(writer, probe, polling_period, MEASUREMENTS_FLUSH_INTERVAL)?;
        }
    }

    Ok(())
}

fn check_domains_consistency(perf_events: &[PowerEvent], power_zones: &PowerZoneHierarchy) -> Vec<RaplDomainType> {
    // get all the domains available via perf-events
    let mut perf_rapl_domains: Vec<RaplDomainType> = perf_events.iter().map(|e| e.domain).collect();
    perf_rapl_domains.sort_by_key(|k| k.to_string());
    perf_rapl_domains.dedup_by_key(|k| k.to_string());

    // get all the domains available via Powercap
    let mut powercap_rapl_domains: Vec<RaplDomainType> = power_zones.flat.iter().map(|z| z.domain).collect();
    powercap_rapl_domains.sort_by_key(|k| k.to_string());
    powercap_rapl_domains.dedup_by_key(|k| k.to_string());

    if perf_rapl_domains != powercap_rapl_domains {
        warn!("Powercap and perf-event don't report the same RAPL domains. This may be due to a bug in powercap or in perf-event.");
        warn!("Upgrading to a newer kernel could fix the problem.");
        warn!("Perf-event: {}", mkstring(&perf_rapl_domains, ", "));
        warn!("Powercap:   {}", mkstring(&powercap_rapl_domains, ", "));

        match rapl_probes::msr::cpu_vendor() {
            Ok(RaplVendor::Amd) =>
                warn!(
                    "AMD cpus only supports the \"pkg\" domain (and sometimes \"core\"), but their support is buggy on old Linux kernels!

                    - All events are present in the sysfs, but they should not be there. This seems to have been fixed in Linux 5.17.
                    See https://github.com/torvalds/linux/commit/0036fb00a756a2f6e360d44e2e3d2200a8afbc9b.

                    - The \"core\" domain doesn't work in perf-event, it could be added soon, if it's supported.
                    See https://lore.kernel.org/lkml/20230217161354.129442-1-wyes.karny@amd.com/T/.

                    NOTE: It could also be totally unsupported, because it gives erroneous/aberrant values in powercap on our bi-socket AMD EPYC 7702 64-core Processor.
                    "
                ),
            Ok(_) => (),
            Err(e) =>
                // not dramatic, we can proceed
                warn!(
                    "Failed to detect the cpu vendor. {}",
                    e
                ),
        };
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

#[cfg(all(feature = "bad_sleep", feature = "bad_sleep_singlethread"))]
compile_error!("features \"bad_sleep\" and \"bad_sleep_singlethread\" cannot be enabled at the same time");
