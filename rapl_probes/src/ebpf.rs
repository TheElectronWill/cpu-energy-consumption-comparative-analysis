use std::collections::HashSet;

use anyhow::{anyhow, Context};
use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::{Array, MapData, PerfEventArray};
use aya::programs::{self, PerfEvent};
use aya::{include_bytes_aligned, Bpf, BpfError};
use aya_log::BpfLogger;

use bytes::BytesMut;
use log::{debug, warn};

use super::perf_event::{pmu_type, PowerEvent};
use super::{CpuId, EnergyProbe, RaplDomainType};

// See EbpfProbe::new
const BUF_PAGE_COUNT: usize = 8;
const EVENT_BYTE_COUNT: usize = 8;

/// EBPF perf event probe.
pub struct EbpfProbe {
    // keeps the bpf program and its maps alive
    // (the DESCRIPTORS map must not be dropped, otherwise the ebpf program won't be able to read it)
    _bpf: Bpf,

    /// The buffers that receive the values of the energy counters from the EBPF program
    buffers: Vec<EbpfEnergyBuffer>,
}

struct EbpfEnergyBuffer {
    buf: PerfEventArrayBuffer<MapData>,
    scale: f64,
    socket: u32,
    domain: RaplDomainType,
}

impl EbpfProbe {
    pub fn new(cpus: &[CpuId], events: &[&PowerEvent], freq_hz: u64) -> anyhow::Result<EbpfProbe> {
        check_socket_cpus(cpus)?;

        let mut bpf = prepare_ebpf_probe(cpus, events, freq_hz)?;

        // Open the event array and store the pointer in the struct,
        // to be able to poll the event buffer and retrieve the values in read_uj
        let mut events_array = PerfEventArray::try_from(bpf.take_map("EVENTS").expect("map not found: EVENTS"))?;

        // The events are pushed to a ring buffer by the bpf program.
        // The ring buffer is created and accessed through `mmap` (in `PerfEventArray::open`).
        // Here, we allocate more pages in order not to lose events.
        // Aya takes care of adding the mandatory first page, so our `pages` variable is the `n`
        // in `1 + 2^n` of the `perf_event_open` manual (see `man 2 perf_event_open`).
        let pages = Some(BUF_PAGE_COUNT);

        // open every event for each cpu
        let mut buffers = Vec::new();
        for CpuId { cpu, socket } in cpus {
            for (i, event) in events.iter().enumerate() {
                let index = cpu + i as u32;
                let buf = events_array.open(index, pages).context("failed to open event array")?;
                buffers.push(EbpfEnergyBuffer {
                    buf,
                    scale: event.scale as f64,
                    socket: *socket,
                    domain: event.domain,
                })
            }
        }
        Ok(EbpfProbe { _bpf: bpf, buffers })
    }
}

impl EnergyProbe for EbpfProbe {
    fn read_consumed_energy(&mut self, measurements: &mut super::EnergyMeasurements) -> anyhow::Result<()> {
        let mut out_bufs: [BytesMut; BUF_PAGE_COUNT] = std::array::from_fn(|_| BytesMut::zeroed(EVENT_BYTE_COUNT));

        for energy_buf in &mut self.buffers {
            // read data from the perf event array, if possible
            let input = &mut energy_buf.buf;
            if input.readable() {
                // this will clear the buffers and copy the pending events into them
                let events_stats = input.read_events(&mut out_bufs).expect("failed to poll events");
                debug_assert_eq!(events_stats.lost, 0);

                // parse the energy counter from the bytes that have been read
                for i_event in 0..events_stats.read {
                    let data = &out_bufs[i_event];
                    let len = data.len();
                    debug!("polled bufs[{i_event}] = {data:x} (len {len})");
                    // debug_assert_eq!(len, EVENT_BYTE_COUNT); not true

                    let counter_value = u64::from_ne_bytes(data[..EVENT_BYTE_COUNT].try_into()?);
                    debug!("=> raw counter value {counter_value}");

                    measurements.push(energy_buf.socket, energy_buf.domain, counter_value, energy_buf.scale);
                }
            }
        }
        Ok(())
    }
}

fn check_socket_cpus(cpus: &[CpuId]) -> anyhow::Result<()> {
    let mut seen_sockets: HashSet<u32> = HashSet::new();
    for cpu_info in cpus {
        let s = cpu_info.socket;
        if !seen_sockets.insert(s) {
            return Err(anyhow!(
                "At most one CPU should be given per socket, wrong cpus for socket {}",
                s
            ));
        }
    }
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

fn prepare_ebpf_probe(socket_cpus: &[CpuId], events: &[&PowerEvent], freq_hz: u64) -> anyhow::Result<Bpf> {
    let mut bpf = load_ebpf_code()?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // fill N_EVENTS
    {
        let mut n_array = Array::try_from(bpf.map_mut("N_EVENTS").expect("map not found: N_EVENTS"))?;
        n_array.set(0, events.len() as i8, 0)?;
    }

    // fill DESCRIPTORS
    {
        // Get a reference to the DESCRIPTORS map
        let mut fd_array = PerfEventArray::try_from(bpf.map_mut("DESCRIPTORS").expect("map not found: DESCRIPTORS"))?;

        // Call perf_event_open for each event and each cpu (the callee should give one cpu per socket)
        let pmu_type = pmu_type().context("get pmu_type")?;
        for cpu_info in socket_cpus {
            for (i, event) in events.iter().enumerate() {
                let cpu_id = cpu_info.cpu;
                let fd = event.perf_event_open(pmu_type, cpu_id)?;
                let index = cpu_id + i as u32;
                fd_array.set(index, fd)?;
            }
        }
    }

    // Find the eBPF program named "aya_start", as a `PerfEvent` program
    let program: &mut PerfEvent = bpf.program_mut("aya_start").unwrap().try_into()?;

    // Load the program: inject its instructions into the kernel
    program.load()?;
    debug!("ebpf program loaded");

    // Attach the program to the hooks in the kernel, in order to be triggered when some events occur
    // The signature of the `attach` method depends on the type of the program, here it's a `PerfEvent`.
    for cpu_info in socket_cpus {
        // This will raise scheduled events on each CPU at <freq> HZ, triggered by the kernel based on clock ticks.
        program.attach(
            programs::perf_event::PerfTypeId::Software,
            programs::perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            programs::perf_event::PerfEventScope::AllProcessesOneCpu { cpu: cpu_info.cpu },
            programs::perf_event::SamplePolicy::Frequency(freq_hz),
        )?;
        debug!("program attached to cpu {cpu_info:?} with frequency {freq_hz}");
    }

    Ok(bpf)
}
