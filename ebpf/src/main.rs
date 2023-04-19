#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_get_smp_processor_id,
    // helpers::bpf_get_numa_node_id,
    macros::{map, perf_event},
    maps::PerfEventArray,
    programs::PerfEventContext,
};
use aya_log_ebpf::{error, debug};

#[map]
static mut DESCRIPTORS: PerfEventArray<i32> = PerfEventArray::with_max_entries(128, 0);

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
    
    #[cfg(debug_assertions)]
    match ctx.pid() {
        0 => debug!(
            ctx,
            "perf_event 'perftest' triggered on CPU {}, running a kernel task", cpu
        ),
        pid => debug!(
            ctx,
            "perf_event 'perftest' triggered on CPU {}, running PID {}", cpu, pid
        ),
    }
    // read PMU data from file descriptor in the array, by cpu id
    let value = unsafe { DESCRIPTORS.read_at_index(cpu)? };

    #[cfg(debug_assertions)]
    debug!(ctx, "got value {} at cpu {}", value.counter, cpu);

    // push the update to userspace, using bpf_perf_event_output (wrapped) with
    // BPF_F_CURRENT_CPU as a flag (done by output_current_cpu).
    unsafe { EVENTS.output_at_index(ctx, &value.counter, cpu) };

    Ok(0)
}

/// Makes the compiler happy, but is never used (eBPF programs cannot panic).
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
