use std::time::Duration;

use anyhow::Context;
use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::perf::bytes::BytesMut;
use aya::maps::PerfEventArray;
use aya::programs::{perf_event, PerfEvent, PerfEventScope};
use aya::{include_bytes_aligned, Bpf, BpfError};
use aya_log::BpfLogger;

use log::{info, warn};

mod rapl;
mod powercap;

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
    let mut events_array = PerfEventArray::try_from(bpf.take_map("EVENTS").expect("map not found: EVENTS"))?;
    let mut fd_array = PerfEventArray::try_from(bpf.take_map("DESCRIPTORS").expect("map not found: DESCRIPTORS"))?;
    println!("ebpf maps found");

    // Find the values for perf_event_open
    let rapl_events = dbg!(rapl::all_power_events()).context("failed to get power events")?;
    let socket_cpus = dbg!(rapl::cpus_to_monitor()).context("failed to get socket cpus")?;
    let pmu_type = dbg!(rapl::pmu_type()).context("failed to get pmu type")?;

    // Call perf_event_open for each event and each cpu, and populate the array with the file descriptors
    // NB: the AMD node we have only supports the "pkg" domain event, so we only use this one.
    // A bug in the Linux kernel makes all events available in the sysfs (so in our `rapl_events`),
    // see https://github.com/torvalds/linux/commit/0036fb00a756a2f6e360d44e2e3d2200a8afbc9b.
    let pkg_event = rapl_events.iter().find(|e| e.name == "pkg").context("no pkg event")?;
    for cpu in &socket_cpus {
        println!("Opening {pkg_event:?} on cpu {cpu}");
        let fd = pkg_event.perf_event_open(pmu_type, PerfEventScope::AllProcessesOneCpu { cpu: *cpu })?;
        // use the cpu id as the index
        fd_array.set(*cpu, fd)?;
    }

    // Find the eBPF program named "aya_start", as a `PerfEvent` program
    let program: &mut PerfEvent = bpf.program_mut("aya_start").unwrap().try_into()?;

    // Load the program: inject its instructions into the kernel
    program.load()?;
    println!("ebpf program loaded");

    // Attach the program to the hooks in the kernel, in order to be triggered when some events occur
    // The signature of the `attach` method depends on the type of the program, here it's a `PerfEvent`.
    for cpu in &socket_cpus {
        // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based on clock ticks.
        program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu: *cpu },
            perf_event::SamplePolicy::Frequency(1),
        )?;
    }

    // Continuously poll the data from the event buffer
    println!("Polling the data...");
    let mut opened: Vec<PerfEventArrayBuffer<_>> = socket_cpus.iter().map(|cpu| events_array.open(cpu.clone(), None).expect("failed to open event array")).collect();
    let mut out_bufs = [BytesMut::new()];
    loop {
        for (cpu, receive_buf) in opened.iter_mut().enumerate() {
            // read data from the perf_event array
            if receive_buf.readable() {
                let res = receive_buf.read_events(&mut out_bufs).expect("failed to poll events");
                let data = &out_bufs[0];
                let len = data.len();
                info!("polled {res:?} = {data:x} (len {len})");
                let counter = u64::from_ne_bytes(data[..8].try_into()?);
                info!("counter = {counter} on cpu {cpu}");
            }
        }
        std::thread::sleep(Duration::from_secs(1).mul_f32(0.5));
    }
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

// TODO monitor more than just the pkg
