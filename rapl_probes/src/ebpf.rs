use anyhow::Context;
use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::{Array, MapData, PerfEventArray};
use aya::programs::{self, PerfEvent};
use aya::{include_bytes_aligned, Bpf, BpfError};
use aya_log::BpfLogger;

use bytes::BytesMut;
use log::{debug, warn};
use std::os::fd::OwnedFd;
use std::os::fd::FromRawFd;

use ebpf_common::RaplEnergy;
use crate::{perf_event, EnergyMeasurements};
use super::perf_event::{pmu_type, PowerEvent};
use super::{CpuId, EnergyProbe, RaplDomainType};

// See EbpfProbe::new
const BUF_PAGE_COUNT: usize = 8;

/// EBPF perf event probe.
pub struct EbpfProbe {
    // keeps the bpf program and its maps alive
    // (the DESCRIPTORS map must not be dropped, otherwise the ebpf program won't be able to read it)
    _bpf: Bpf,

    /// The buffers that receive the values of the energy counters from the EBPF program
    buffers: Vec<EbpfEnergyBuffer>,

    /// Stores the energy measurements
    measurements: EnergyMeasurements,
}

#[derive(Debug)]
struct DomainInfo {
    domain: RaplDomainType,
    scale: f32,
}

struct EbpfEnergyBuffer {
    buf: PerfEventArrayBuffer<MapData>,
    cpu: CpuId,
    domains_by_id: Vec<DomainInfo>,
}

impl EbpfProbe {
    pub fn new(cpus: &[CpuId], events: &[&PowerEvent], freq_hz: u64) -> anyhow::Result<EbpfProbe> {
        crate::check_socket_cpus(cpus)?;

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
        for c @ CpuId { cpu, socket: _ } in cpus {
            let index = *cpu;
            let domains_by_id = events.into_iter().map(|evt| DomainInfo{domain: evt.domain, scale: evt.scale}).collect();
            
            debug!("Opening EVENTS[{index}] for domains {domains_by_id:?}");
            let buf = events_array.open(index, pages).context("failed to open event array")?;

            buffers.push(EbpfEnergyBuffer {
                buf,
                cpu: *c,
                domains_by_id,
            })
        }
        Ok(EbpfProbe {
            _bpf: bpf,
            buffers,
            measurements: EnergyMeasurements::new(cpus.len()),
        })
    }
}

impl EnergyProbe for EbpfProbe {
    fn poll(&mut self) -> anyhow::Result<()> {
        let mut out_bufs: [BytesMut; BUF_PAGE_COUNT] = std::array::from_fn(|_| BytesMut::new());

        for energy_buf in &mut self.buffers {
            // read data from the perf event array, if possible
            let input_buf = &mut energy_buf.buf;
            if input_buf.readable() {
                // this will clear the buffers and copy the pending events into them
                let events_stats = input_buf.read_events(&mut out_bufs).expect("failed to poll events");
                debug_assert_eq!(events_stats.lost, 0);

                // parse the energy counter (and more) from the bytes that have been read
                // See another example at https://github.com/aya-rs/book/blob/4aa9a5b38a0d4b6a05debcb213e5540820eda1fd/examples/cgroup-skb-egress/cgroup-skb-egress/src/main.rs#L68
                for data_buf in out_bufs.iter_mut().take(events_stats.read) {
                    let len = data_buf.len();
                    debug!("polled data from out_bufs = {data_buf:x} (len {len})");

                    // the ebpf program pushes pointers to RaplEnergy structs,
                    // we convert the pointer type and read the struct from it
                    let ptr = data_buf.as_ptr() as *const RaplEnergy;
                    let data: RaplEnergy = unsafe { ptr.read_unaligned() };
                    debug!("=> data for cpu {} domain {} = {}", data.cpu_id, data.domain_id, data.energy);

                    let rapl_domain_info = &energy_buf.domains_by_id[data.domain_id as usize];

                    self.measurements.push(
                        energy_buf.cpu.socket,
                        rapl_domain_info.domain,
                        data.energy,
                        perf_event::PERF_MAX_ENERGY,
                        rapl_domain_info.scale as f64,
                    );
                }
            } else {
                debug!("buffer of cpu {:?} is not readable (if this occurs once at the beginning, this is not a problem)", energy_buf.cpu);
            }
        }
        Ok(())
    }

    fn measurements(&self) -> &crate::EnergyMeasurements {
        &self.measurements
    }
    
    fn reset(&mut self) {
        self.measurements.clear()
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

fn prepare_ebpf_probe(socket_cpus: &[CpuId], events: &[&PowerEvent], freq_hz: u64) -> anyhow::Result<Bpf> {
    let mut bpf = load_ebpf_code()?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // fill N_EVENTS
    {
        let mut n_array = Array::try_from(bpf.map_mut("N_EVENTS").expect("map not found: N_EVENTS"))?;
        let n = i8::try_from(events.len()).with_context(|| format!("too many events: {}", events.len()))?;
        n_array.set(0, n, 0)?;
        debug!("N_EVENTS[0] = {n}");
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
                let fd = unsafe{OwnedFd::from_raw_fd(fd)};
                let index = cpu_id + i as u32;
                fd_array.set(index, &fd)?;
                debug!("DESCRIPTORS[{index}] = {fd:?}");
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
