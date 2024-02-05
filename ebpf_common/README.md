# How to use eBPF probes

This crate contains common code for eBPF-based measurement of RAPL perf-events. A starting point for this work has been the "bpf-perf" C examples, see [this commit in the Linux kernel repository](https://github.com/torvalds/linux/commit/d74a790d5237e7f56677030d932bc4f37ec36c92#diff-7f8cb9786a9d6a03f0164b2a9c2b942ab954866edc616a700c8884333d52a672) and [the description of the feature](https://lwn.net/Articles/651461/).

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
2. Install a rust nightly toolchain with the rust-src component: `rustup toolchain install nightly --component rust-src`
3. Install bpf-linker: `cargo install bpf-linker`
4. Download our [modified version of aya](https://github.com/TheElectronWill/aya/commit/0aeb379bebde2a7c1b87ec8e0e66713a877daef0): download the whole repository at the given commit, and place the uncompressed directory next to the root directory of the measurement tool's directory.
5. Uncomment the last lines of the root [Cargo.toml](../Cargo.toml).

## Build eBPF mini-program

First, build the eBPF program that will be loaded into the kernel.
```bash
cargo xtask build-ebpf --release
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build CLI app

```bash
cargo build --features enable_ebpf --release --bin cli_poll_rapl
```

## Run

```bash
sudo -E ./target/x86_64-unknown-linux-musl/release/cli_poll_rapl poll ebpf --domains pkg -f 1 -o stdout
```

Debug tip: remove `--release` flags and add environment variable `RUST_LOG=debug`
