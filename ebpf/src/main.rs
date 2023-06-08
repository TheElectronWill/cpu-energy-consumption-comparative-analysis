#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_get_smp_processor_id,
    // helpers::bpf_get_numa_node_id,
    macros::{map, perf_event},
    maps::{Array, PerfEventArray},
    programs::PerfEventContext,
};
use aya_log_ebpf::{debug, error};
use ebpf_common::RaplEnergy;

/// Input map (single value): the number of perf events for each socket
#[map]
static mut N_EVENTS: Array<u8> = Array::with_max_entries(1, 0);

/// Input maps: the file descriptors of the RAPL perf events.
/// There is one map for all the RAPL domains.
///
/// For each CPU socket, the first monitored event is at the index of the socket's first CPU.
/// Example with 2 sockets and 2 events:
/// ```txt
/// [s0_event0, s0_event1, ...<default value>..., s1_event0, s1_event1, ...]
///  ^                                            ^  
/// the 1st cpu of the                     the 1st cpu of the
/// 1st socket is cpu 0                    2nd socket is cpu N
/// ```
#[map]
static mut DESCRIPTORS: PerfEventArray<i32> = PerfEventArray::with_max_entries(128, 0);

/// Output map: the event data (i.e. the values of the RAPL counters).
///
/// ## Note
/// We CANNOT output the values at any index, we can only output values at the index equal to the current cpu.
/// Reading the perf events from DESCRIPTORS works fine, but bpf_perf_event_output doesn't work.
/// See https://github.com/iovisor/bcc/issues/2857#issuecomment-608368322
///
#[map]
static mut EVENTS: PerfEventArray<RaplEnergy> = PerfEventArray::with_max_entries(128, 0);

#[perf_event]
pub fn aya_start(ctx: PerfEventContext) -> i32 {
    match try_aya_start(&ctx) {
        Ok(()) => 0,
        Err((msg, ret)) => {
            error!(&ctx, "ebpf program failed with error {}: {}", ret, msg);
            1
        }
    }
}

fn read_and_push_counter(ctx: &PerfEventContext, cpu_id: u32, domain_id: u8) -> Result<(), (&str, i64)> {
    // read the RAPL energy counter from the file descriptor at the given index
    let read_index = cpu_id + domain_id as u32;
    let value = unsafe { DESCRIPTORS.read_at_index(read_index) }.map_err(|e| ("read", e))?;
    let energy = value.counter;
    
    #[cfg(debug_assertions)]
    debug!(ctx, "got value {} from fd DESCRIPTORS[{}]", energy, read_index);

    // push the value to userspace (this internally calls bpf_perf_event_output)
    let write_index = cpu_id; // we can only output at the index of the current cpu
    let data = RaplEnergy {
        cpu_id,
        domain_id,
        energy,
    };
    unsafe { EVENTS.output_at_index(ctx, &data, write_index) }.map_err(|e| ("output", e))?;

    Ok(())
}

fn try_aya_start(ctx: &PerfEventContext) -> Result<(), (&str, i64)> {
    let cpu_id = unsafe { bpf_get_smp_processor_id() };

    // loops aren't available in EBPF before Linux Kernel 5.3, and we have HPC servers running on 4.8
    // For brevity, only the common cases used in our benchmarks are implemented.

    let n = unsafe { N_EVENTS.get(0) }.ok_or(("N_EVENTS not set", -1))?;

    #[cfg(debug_assertions)]
    debug!(ctx, "N_EVENTS = {}", *n);

    match n {
        1 => read_and_push_counter(ctx, cpu_id, 0)?,
        2 => {
            read_and_push_counter(ctx, cpu_id, 0)?;
            read_and_push_counter(ctx, cpu_id, 1)?;
        }
        3 => {
            read_and_push_counter(ctx, cpu_id, 0)?;
            read_and_push_counter(ctx, cpu_id, 1)?;
            read_and_push_counter(ctx, cpu_id, 2)?;
        }
        4 => {
            read_and_push_counter(ctx, cpu_id, 0)?;
            read_and_push_counter(ctx, cpu_id, 1)?;
            read_and_push_counter(ctx, cpu_id, 2)?;
            read_and_push_counter(ctx, cpu_id, 3)?;
        }
        5 => {
            read_and_push_counter(ctx, cpu_id, 0)?;
            read_and_push_counter(ctx, cpu_id, 1)?;
            read_and_push_counter(ctx, cpu_id, 2)?;
            read_and_push_counter(ctx, cpu_id, 3)?;
            read_and_push_counter(ctx, cpu_id, 4)?;
        }
        _ => {
            return Err(("invalid N_EVENTS, should be in 1..=5", -7));
        }
    }

    Ok(())
}

/// Makes the compiler happy, but is never used (eBPF programs cannot panic).
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
