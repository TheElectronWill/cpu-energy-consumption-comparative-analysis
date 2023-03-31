# Read ebpf RAPL values from Rust

Inspired from the C version, see [this commit in the Linux kernel repository](https://github.com/torvalds/linux/commit/d74a790d5237e7f56677030d932bc4f37ec36c92#diff-7f8cb9786a9d6a03f0164b2a9c2b942ab954866edc616a700c8884333d52a672) and [the description of the feature](https://lwn.net/Articles/651461/).

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain with the rust-src component: `rustup toolchain install nightly --component rust-src`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
