use anyhow::Context;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use userspace::probes::{self, perf_rapl::PowerEvent, powercap::PowercapProbe, Probe};

fn init_powercap_probe() -> anyhow::Result<PowercapProbe> {
    let powercap_zones = probes::powercap::all_power_zones()?;
    let pkg_zone = powercap_zones.iter().find(|z| z.name == "package-0").context(":'(")?;
    probes::powercap::PowercapProbe::new(&vec![(pkg_zone, 0u32)])
}

fn init_perf_event() -> anyhow::Result<(Vec<u32>, PowerEvent)> {
    let mut events = probes::perf_rapl::all_power_events()?;
    let cpus = probes::perf_rapl::cpus_to_monitor()?;
    let (pkg_event_i, _) = events
        .iter()
        .enumerate()
        .find(|(_i, e)| e.name == "pkg")
        .context(":'(")?;
    let pkg_event = events.swap_remove(pkg_event_i);
    Ok((cpus, pkg_event))
}

fn criterion_benchmark(c: &mut Criterion) {
    // setup
    let (socket_cpus, perf_event) = init_perf_event().unwrap();
    let mut powercap = init_powercap_probe().unwrap();
    let mut perf_userspace = probes::perf_rapl::PerfEventProbe::new(&socket_cpus, &perf_event).unwrap();

    let mut group = c.benchmark_group("RAPL");
    group.significance_level(0.01).sample_size(1000);
    group.bench_function("powercap-sysfs", |b| b.iter(|| black_box(powercap.read_uj())));
    group.bench_function("perf-userspace", |b| b.iter(|| black_box(perf_userspace.read_uj())));

    // ebpf requires the tokio runtime to asynchronously poll the buffers
    {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut perf_ebpf =
            runtime.block_on(async { probes::ebpf::EbpfProbe::new(&socket_cpus, &perf_event, 50_000).unwrap() });
        group.bench_function("perf-ebpf", |b| b.iter(|| black_box(perf_ebpf.read_uj())));
        group.bench_function("perf-ebpf-busywait", |b| {
            b.iter(|| {
                let mut measurements = perf_ebpf.read_uj().unwrap();
                while measurements.is_empty() {
                    measurements = perf_ebpf.read_uj().unwrap();
                }
                black_box(measurements);
            })
        });
        group.bench_function("math-conversions", |b| {
            b.iter(|| {
                let raw = black_box(123456u64);
                let joules = (raw as f64) * 2.3283064365386962890625e-10;
                let u_joules = (joules * 1000_000.0) as u64;
                black_box(u_joules);
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
