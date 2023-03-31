#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_smp_processor_id, bpf_perf_event_read},
    macros::{map, perf_event},
    maps::{PerfEventArray, Array},
    programs::PerfEventContext,
    BpfContext, cty::c_void,
};
use aya_log_ebpf::{info, error};

// TODO: this needs to be a bpf map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY, otherwise
// we cannot call bpf_perf_event_read on it.
// But! aya's PerfEventArray doesn't provide the `set` method, only `Array` provides it...
#[map]
static mut DESCRIPTORS: PerfEventArray<i32> = PerfEventArray::with_max_entries(32, 0);

#[map]
static mut EVENTS: PerfEventArray<u64> = PerfEventArray::with_max_entries(32, 0);

#[perf_event]
pub fn aya_start(ctx: PerfEventContext) -> i32 {
    match try_aya_start(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "ebpf program failed with error {}", ret);
            1
        },
    }
}

fn try_aya_start(ctx: &PerfEventContext) -> Result<i32, i64> {
    let cpu = unsafe { bpf_get_smp_processor_id() };
    match ctx.pid() {
        0 => info!(
            ctx,
            "perf_event 'perftest' triggered on CPU {}, running a kernel task", cpu
        ),
        pid => info!(
            ctx,
            "perf_event 'perftest' triggered on CPU {}, running PID {}", cpu, pid
        ),
    }
    // read PMU data from file descriptor in the array, by cpu id
    let key = cpu.into();
    let value = unsafe { DESCRIPTORS.read_at_index(key)? };

    info!(ctx, "got value {} at cpu {}", value.counter, cpu);

    // push the update to userspace, using bpf_perf_event_output (wrapped) with
    // BPF_F_CURRENT_CPU as a flag (done by output_current_cpu).
    //unsafe { EVENTS.output_current_cpu(ctx, &value.counter) };

    Ok(0)
}

/// Converts a mutable reference to a C pointer `*void`.
fn as_void_ptr<T>(t: &mut T) -> *mut c_void {
    return t as *mut _ as *mut c_void
}

/// Makes the compiler happy, but is never used (eBPF programs cannot panic).
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
