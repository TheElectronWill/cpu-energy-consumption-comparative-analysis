use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rapl_probes::{
    msr::MsrProbe,
    perf_event::{self, PerfEventProbe},
    powercap::{self, PowercapProbe},
    EnergyProbe, RaplDomainType,
};

#[cfg(feature = "bench_ebpf")]
use rapl_probes::ebpf::EbpfProbe;

fn init_powercap_probe<const CHECK_UTF: bool>(domains: &[RaplDomainType]) -> anyhow::Result<PowercapProbe<CHECK_UTF>> {
    let cpus = rapl_probes::cpus_to_monitor()?;
    let all = powercap::all_power_zones()?.flat;
    let zones: Vec<&powercap::PowerZone> = all.iter().filter(|z| domains.contains(&z.domain)).collect();
    PowercapProbe::new(&cpus, &zones)
}

fn init_perf_probe(domains: &[RaplDomainType]) -> anyhow::Result<PerfEventProbe> {
    let cpus = rapl_probes::cpus_to_monitor()?;
    let all = perf_event::all_power_events()?;
    let events: Vec<&perf_event::PowerEvent> = all.iter().filter(|e| domains.contains(&e.domain)).collect();
    PerfEventProbe::new(&cpus, &events)
}

#[cfg(feature = "bench_ebpf")]
fn init_ebpf_probe(domains: &[RaplDomainType]) -> anyhow::Result<EbpfProbe> {
    let all = perf_event::all_power_events()?;
    let cpus = rapl_probes::cpus_to_monitor()?;
    let events: Vec<&perf_event::PowerEvent> = all.iter().filter(|e| domains.contains(&e.domain)).collect();
    let freq_hz = 1000;
    EbpfProbe::new(&cpus, &events, freq_hz)
}

fn init_msr_probe(domains: &[RaplDomainType]) -> anyhow::Result<MsrProbe> {
    let cpus = rapl_probes::cpus_to_monitor()?;
    MsrProbe::new(&cpus, domains)
}

fn criterion_benchmark(c: &mut Criterion) {
    let domains_lists: [(&str, &[RaplDomainType]); 5] = [
        ("1", &[RaplDomainType::Package]),
        ("2", &[RaplDomainType::Package, RaplDomainType::PP0]),
        (
            "3",
            &[RaplDomainType::Package, RaplDomainType::PP0, RaplDomainType::Platform],
        ),
        ("5name", &RaplDomainType::ALL),
        ("5ordered", &RaplDomainType::ALL_IN_ADDR_ORDER),
    ];

    // criterion config
    let mut group = c.benchmark_group("RAPL");
    group
        .significance_level(0.005)
        .sample_size(1000)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(10));

    // benchmark definitions for each list of RAPL domains
    for (id, domains) in domains_lists {
        let mut probe_powercap = init_powercap_probe::<true>(&domains).unwrap();
        let mut probe_powercap_unchecked = init_powercap_probe::<false>(&domains).unwrap();
        let mut probe_perf = init_perf_probe(&domains).unwrap();
        let mut probe_msr = init_msr_probe(&domains).unwrap();

        // Most of the time spent by the ebpf probe is kernel time, not user time, and it's not measured by criterion.
        // Therefore, it's disabled by default.
        #[cfg(feature = "bench_ebpf")]
        let runtime = tokio::runtime::Runtime::new().unwrap(); // ebpf requires the tokio runtime to asynchronously poll the buffers
        #[cfg(feature = "bench_ebpf")]
        let mut probe_ebpf = runtime.block_on(async { init_ebpf_probe(&domains).unwrap() });

        // the benchmark
        let mut run_bench = |name: &str, probe: &mut dyn EnergyProbe| {
            let id = BenchmarkId::new(name, id);
            group.bench_function(id, |b| {
                probe.reset();
                b.iter(|| {
                    probe.poll().unwrap();
                    black_box(probe.measurements()); // prevent compiler optimizations from removing the measurement
                })
            });
        };

        // run it
        run_bench("powercap-sysfs", &mut probe_powercap);
        run_bench("powercap-sysfs-unchecked", &mut probe_powercap_unchecked);
        run_bench("perf-event-user", &mut probe_perf);
        run_bench("msr-lowlevel", &mut probe_msr);
        #[cfg(feature = "bench_ebpf")]
        run_bench("perf-event-ebpf", &mut probe_msr);
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
