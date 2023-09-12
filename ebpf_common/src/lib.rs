#![no_std]

// This library contains code that is shared between the `ebpf` module (ebpf kernel program)
// and the `rapl_probes` module, which implements the userspace program that communicates with the ebpf kernel program.

/// The value of a RAPL energy counter.
#[repr(align(16))] // for the ebpf verifier
pub struct RaplEnergy {
    pub cpu_id: u32,
    pub domain_id: u8,
    pub energy: u64,
}
