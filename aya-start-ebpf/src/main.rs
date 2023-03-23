#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_get_smp_processor_id, macros::perf_event, programs::PerfEventContext, BpfContext,
};
use aya_log_ebpf::info;

#[perf_event]
pub fn aya_start(ctx: PerfEventContext) -> u32 {
    match try_aya_start(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_aya_start(ctx: PerfEventContext) -> Result<u32, u32> {
    let cpu = unsafe { bpf_get_smp_processor_id() };
    match ctx.pid() {
        0 => info!(
            &ctx,
            "perf_event 'perftest' triggered on CPU {}, running a kernel task", cpu
        ),
        pid => info!(
            &ctx,
            "perf_event 'perftest' triggered on CPU {}, running PID {}", cpu, pid
        ),
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
