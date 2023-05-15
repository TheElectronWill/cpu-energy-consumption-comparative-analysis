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

/// Input map (single value): the number of perf events for each socket
#[map]
static mut N_EVENTS: Array<i8> = Array::with_max_entries(1, 0);

/// Input map: the file descriptors of the RAPL perf events.
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

/// Output map: the event data (i.e. the values of the RAPL counters)
#[map]
static mut EVENTS: PerfEventArray<u64> = PerfEventArray::with_max_entries(128, 0);

#[perf_event]
pub fn aya_start(ctx: PerfEventContext) -> i32 {
    match try_aya_start(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "ebpf program failed with error {}", ret);
            1
        }
    }
}

fn try_aya_start(ctx: &PerfEventContext) -> Result<i32, i64> {
    let cpu = unsafe { bpf_get_smp_processor_id() };

    // loops aren't available in EBPF before Linux Kernel 5.3, and we have HPC servers running on 4.8
    // For brevity, only the common cases used in our benchmarks are implemented.
    let n = unsafe { N_EVENTS.get(0) }.ok_or(-6)?;
    match n {
        1 => {
            // only one event
            read_and_push_counter(ctx, cpu)?;
        }
        2 => {
            // all RAPL events available on AMD processors
            read_and_push_counter(ctx, cpu)?;
            read_and_push_counter(ctx, cpu + 1)?;
        }
        5 => {
            // all RAPL events available on recent Intel processors
            read_and_push_counter(ctx, cpu)?;
            read_and_push_counter(ctx, cpu + 1)?;
            read_and_push_counter(ctx, cpu + 2)?;
            read_and_push_counter(ctx, cpu + 3)?;
            read_and_push_counter(ctx, cpu + 4)?;
        }
        _ => {
            // unsupported
            return Err(-7);
        }
    };

    Ok(0)
}

fn read_and_push_counter(ctx: &PerfEventContext, index: u32) -> Result<i32, i64> {
    // read PMU data from file descriptor in the array, by cpu id
    let value = unsafe { DESCRIPTORS.read_at_index(index)? };

    #[cfg(debug_assertions)]
    debug!(ctx, "got value {} at index {}", value.counter, index);

    // push the update to userspace, using bpf_perf_event_output (wrapped)
    unsafe { EVENTS.output_at_index(ctx, &value.counter, index) };

    Ok(0)
}

/// Makes the compiler happy, but is never used (eBPF programs cannot panic).
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
