# RAPL probes benchmarks

## Criterion benchmarks (benches/)

Benchmark the functions that read the RAPL counters, with the *criterion* tool.

Results are in [target/criterion/report/index.html](../target/criterion/report/index.html).

### How to run

Running the benchmarks require to execute `cargo bench` **twice**, as follows:

1. Compile and attempt to run with `cargo bench`. It will fail with a panick, because the compiled binary does not have the required linux capabilities and thus cannot access the RAPL counters.
2. Add capabilities to the binary file: `sudo setcap cap_sys_rawio,cap_sys_admin=ep ../target/x86_64-unknown-linux-musl/release/deps/benchmark_probes-*`
3. Run the microbenchmark: `cargo bench`

## CLI benchmark app (src/)

A CLI app that runs a benchmark with `sysbench` + RAPL polling.
