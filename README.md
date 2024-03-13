# Minimal RAPL-based measurement tool in Rust

This is a minimal tool that measures the energy consumption of a CPU, on Linux, through all possible RAPL interfaces.

Research paper: *Dissecting the software-based measurement of CPU energy consumption: a comparative analysis*, Guillaume Raffin and Denis Trystram. 

In this paper, we provide an in-depth analysis of the different ways of accessing RAPL measurements, demonstrate an efficient way of implementing them, and offer recommendations based on qualitative and quantitative criterias. Applications include: energy profiling, HPC energy monitoring with minimal performance overhead and maximal frequency (around 1000 Hz), etc.
- [ArXiv link](https://doi.org/10.48550/arXiv.2401.15985), [HAL link](https://hal.science/hal-04420527) (preprint)
- Journal link (coming soon)

Licensed under the EUPL 1.2 or later (The EUPL is compatible with many other licences, including GPL and LGPL, don't hesitate to contact us by mail if you have concerns about it).

## How to use

First, [install Rust](https://rustup.rs/).  
Make sure that you have the `x86_64-unknown-linux-musl` toolchain installed:
```sh
rustup target add x86_64-unknown-linux-musl
```

Then, **compile the project**:
```sh
cargo build --release
```

Finally, run the tool with the appropriate privileges (the easiest way to do that is to run it as root):
```sh
sudo -E ./target/x86_64-unknown-linux-musl/release/cli_poll_rapl poll powercap --domains pkg --frequency 1 --output stdout
```

You can use `--help` to learn about the possible options.

## How to use eBPF

By default, the eBPF implementation is disabled (not compiled, not included in the tool) because it requires additional system and crate dependencies.
To enable it as we did for the paper, see [ebpf_common/README.md](ebpf_common/README.md).
