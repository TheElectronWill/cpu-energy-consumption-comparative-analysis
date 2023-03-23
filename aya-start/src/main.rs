use aya::programs::{perf_event, PerfEvent};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf, BpfError};
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let mut bpf = load_ebpf_program()?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let program: &mut PerfEvent = bpf.program_mut("aya_start").unwrap().try_into()?;
    program.load()?;
    for cpu in online_cpus()? {
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

fn load_ebpf_program() -> Result<Bpf, BpfError> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let ebpf_bytecode = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/aya-start");

    #[cfg(not(debug_assertions))]
    let ebpf_bytecode = include_bytes_aligned!("../../target/bpfel-unknown-none/release/aya-start");
    
    Bpf::load(ebpf_bytecode)
}
