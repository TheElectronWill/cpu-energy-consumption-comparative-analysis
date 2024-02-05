# eBPF program

This crate contains the eBPF program that will be loaded into the kernel.
The common part (shared between userspace and kernelspace) is factored in a separate crate [ebpf_common](../ebpf_common/README.md).

See [here](../ebpf_common/README.md) to learn how to use the eBPF RAPL probe.
