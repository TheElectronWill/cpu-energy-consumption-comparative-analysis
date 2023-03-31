use anyhow::Context;
use aya::maps::{PerfEventArray, Array};
use aya::programs::{perf_event, PerfEvent, PerfEventScope};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf, BpfError};
use aya_log::BpfLogger;

use log::{info, warn};
use tokio::signal;

mod rapl;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let mut bpf = load_ebpf_code()?;
    println!("ebpf code loaded");

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Get a reference to the DESCRIPTORS map
    let mut events_array = PerfEventArray::try_from(bpf.map_mut("EVENTS").expect("map not found: EVENTS"))?;
    let mut fd_array = PerfEventArray::try_from(bpf.map_mut("DESCRIPTORS").expect("map not found: DESCRIPTORS"))?;
    println!("ebpf maps found");

    // Find the values for perf_event_open
    let rapl_events = dbg!(rapl::all_power_events().context("failed to get power events")?);
    let socket_cpus = dbg!(rapl::cpus_to_monitor().context("failed to get socket cpus")?);
    let pmu_type = dbg!(rapl::pmu_type().context("failed to get pmu type")?);

    // Call perf_event_open for each event and each cpu, and populate the array with the file descriptors
    for cpu in socket_cpus {
        for evt in &rapl_events {
            let fd = evt.perf_event_open(pmu_type, PerfEventScope::AllProcessesOneCpu { cpu })?;
            // use the cpu id as the index
            fd_array.set(cpu, fd)?; 
        }
    }

    // Find the eBPF program named "aya_start", as a `PerfEvent` program
    let program: &mut PerfEvent = bpf.program_mut("aya_start").unwrap().try_into()?;

    // Load the program: inject its instructions into the kernel
    program.load()?;
    println!("ebpf program loaded");

    // Attach the program to the hooks in the kernel, in order to be triggered when some events occur
    // The signature of the `attach` method depends on the type of the program, here it's a `PerfEvent`.

    // We must use only one CPU per socket, on my machine it's the CPU 0
    for cpu in vec![0] {
        // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based on clock ticks.
        program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(1),
        )?;
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

/// Loads the BPF bytecode from the compilation result of the "ebpf" module.
fn load_ebpf_code() -> Result<Bpf, BpfError> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let ebpf_bytecode = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/ebpf");

    #[cfg(not(debug_assertions))]
    let ebpf_bytecode = include_bytes_aligned!("../../target/bpfel-unknown-none/release/ebpf");

    Bpf::load(ebpf_bytecode)
}
