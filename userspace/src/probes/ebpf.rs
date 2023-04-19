use anyhow::Context;
use aya::maps::perf::bytes::BytesMut;
use aya::maps::perf::{PerfEventArrayBuffer, AsyncPerfEventArrayBuffer};
use aya::maps::{AsyncPerfEventArray, MapData, PerfEventArray};
use aya::programs::{perf_event, PerfEvent, PerfEventScope};
use aya::{include_bytes_aligned, Bpf, BpfError};
use aya_log::BpfLogger;

use log::{debug, warn};

use super::perf_rapl::{self, PowerEvent};
use super::EnergyMeasurement;

/// EBPF perf event probe.
pub struct EbpfProbe {
    // keeps the bpf program and its maps alive
    // (the DESCRIPTORS map must not be dropped, otherwise the ebpf program won't be able to read it)
    _bpf: Bpf,

    // only open the buffer once
    opened: Vec<PerfEventArrayBuffer<MapData>>,

    /// Like [super::perf_rapl::PerfEventProbe], the counters must be scaled to get a correct value.
    scale: f64,   
}

impl EbpfProbe {
    pub fn new(socket_cpus: &Vec<u32>, event: &PowerEvent, freq: u64) -> anyhow::Result<EbpfProbe> {
        let mut bpf = prepare_ebpf_probe(socket_cpus, event, freq)?;

        // Open the event array and store the pointer in the struct,
        // to be able to poll the event buffer and retrieve the values in read_uj
        let mut events_array = PerfEventArray::try_from(bpf.take_map("EVENTS").expect("map not found: EVENTS"))?;
        
        // The events are pushed to a ring buffer by the bpf program.
        // The ring buffer is created and accessed through `mmap` (in `PerfEventArray::open`).
        // Here, we allocate more pages in order not to lose events.
        // Aya takes care of adding the mandatory first page, so our `pages` variable is the `n`
        // in `1 + 2^n` of the `perf_event_open` manual (see `man 2 perf_event_open`).
        let pages = Some(8);
        let opened: Vec<PerfEventArrayBuffer<_>> = socket_cpus
            .iter()
            .map(|cpu| events_array.open(*cpu, pages).expect("failed to open event array"))
            .collect();
        let scale = event.scale as f64;
        Ok(EbpfProbe {
            _bpf: bpf,
            opened,
            scale,
        })
    }
}

impl super::Probe for EbpfProbe {
    fn read_uj(&mut self, out: &mut Vec<EnergyMeasurement>) -> anyhow::Result<()> {
        let mut out_bufs = [BytesMut::new()]; // TODO try to keep the same BytesMut?
        // TODO allocate multiple BytesMut here

        for (cpu, receive_buf) in self.opened.iter_mut().enumerate() {
            // read data from the perf_event array, if possible
            while receive_buf.readable() {
                let events_stats = receive_buf.read_events(&mut out_bufs).expect("failed to poll events");
                let data = &out_bufs[0];
                let len = data.len();
                debug_assert_eq!(events_stats.lost, 0);

                debug!("polled {events_stats:?} = {data:x} (len {len})");

                let raw = u64::from_ne_bytes(data[..8].try_into()?);
                debug!("=> raw counter value {raw}");

                let joules = (raw as f64) * self.scale;
                let u_joules = (joules * 1000_000.0) as u64;

                out.push(EnergyMeasurement {
                    energy_counter: u_joules,
                    cpu: cpu as u32,
                });
            }
        }
        Ok(())
    }
}

/// Loads the BPF bytecode from the compilation result of the "ebpf" module.
fn load_ebpf_code() -> Result<Bpf, BpfError> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let ebpf_bytecode = include_bytes_aligned!("../../../target/bpfel-unknown-none/debug/ebpf");

    #[cfg(not(debug_assertions))]
    let ebpf_bytecode = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/ebpf");

    Bpf::load(ebpf_bytecode)
}

fn prepare_ebpf_probe(socket_cpus: &Vec<u32>, event: &PowerEvent, freq: u64) -> anyhow::Result<Bpf> {
    let mut bpf = load_ebpf_code()?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Get a reference to the DESCRIPTORS map
    let mut fd_array = PerfEventArray::try_from(bpf.map_mut("DESCRIPTORS").expect("map not found: DESCRIPTORS"))?;

    // Call perf_event_open for each event and each cpu (the callee should give one cpu per socket)
    let pmu_type = perf_rapl::pmu_type().context("get pmu_type")?;
    for cpu in socket_cpus {
        let fd = event.perf_event_open(pmu_type, PerfEventScope::AllProcessesOneCpu { cpu: *cpu })?;
        // use the cpu id as the index
        fd_array.set(*cpu, fd)?;
    }

    // Find the eBPF program named "aya_start", as a `PerfEvent` program
    let program: &mut PerfEvent = bpf.program_mut("aya_start").unwrap().try_into()?;

    // Load the program: inject its instructions into the kernel
    program.load()?;
    debug!("ebpf program loaded");

    // Attach the program to the hooks in the kernel, in order to be triggered when some events occur
    // The signature of the `attach` method depends on the type of the program, here it's a `PerfEvent`.
    for cpu in socket_cpus {
        // This will raise scheduled events on each CPU at <freq> HZ, triggered by the kernel based on clock ticks.
        program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu: *cpu },
            perf_event::SamplePolicy::Frequency(freq),
        )?;
        debug!("program attached to cpu {cpu} with frequency {freq}");
    }
    
    Ok(bpf)
}
