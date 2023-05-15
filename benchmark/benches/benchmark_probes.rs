use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rapl_probes::{
    ebpf::EbpfProbe,
    msr::MsrProbe,
    perf_event::{self, PerfEventProbe},
    powercap::{self, PowercapProbe},
    EnergyMeasurements, EnergyProbe, RaplDomainType,
};

fn init_powercap_probe<const CHECK_UTF: bool>(domains: &[RaplDomainType]) -> anyhow::Result<PowercapProbe<CHECK_UTF>> {
    let all = powercap::all_power_zones()?;
    let zones: Vec<&powercap::PowerZone> = all.iter().filter(|z| domains.contains(&z.domain)).collect();
    PowercapProbe::new(&zones)
}

fn init_perf_probe(domains: &[RaplDomainType]) -> anyhow::Result<PerfEventProbe> {
    let cpus = rapl_probes::cpus_to_monitor()?;
    let all = perf_event::all_power_events()?;
    let events: Vec<&perf_event::PowerEvent> = all.iter().filter(|e| domains.contains(&e.domain)).collect();
    PerfEventProbe::new(&cpus, &events)
}

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
        ("2",&[RaplDomainType::Package, RaplDomainType::PP0]),
        ("3",&[RaplDomainType::Package, RaplDomainType::PP0, RaplDomainType::Platform]),
        ("5name",&RaplDomainType::ALL),
        ("5ordered",&RaplDomainType::ALL_IN_ADDR_ORDER),
    ];

    let socket_count = rapl_probes::cpus_to_monitor().unwrap().len();

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

        // the benchmark
        let mut run_bench = |name: &str, probe: &mut dyn EnergyProbe| {
            let id = BenchmarkId::new(name, id);
            group.bench_function(id, |b| {
                let mut m = EnergyMeasurements::new(socket_count);
                b.iter(|| {
                    probe.read_consumed_energy(&mut m).unwrap();
                    black_box(&m); // prevent compiler optimizations
                })
            });
        };

        // run it
        run_bench("powercap-sysfs", &mut probe_powercap);
        run_bench("powercap-sysfs-unchecked", &mut probe_powercap_unchecked);
        run_bench("perf-event-user", &mut probe_perf);
        run_bench("msr-lowlevel", &mut probe_msr);
    }

    // ebpf requires the tokio runtime to asynchronously poll the buffers
    /*
    {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut perf_ebpf = runtime.block_on(async { init_ebpf_probe(&domains).unwrap() });

        group.bench_function("perf-ebpf", |b| {
            let mut m = EnergyMeasurements::new(socket_count);
            b.iter(|| black_box(perf_ebpf.read_consumed_energy(&mut m)))
        });
        // group.bench_function("perf-ebpf-busywait", |b| {
        //     let mut m = EnergyMeasurements::new(socket_count);
        //     b.iter(|| {
        //         let mut measurements = perf_ebpf.read_consumed_energy(&mut m).unwrap();
        //         while measurements.is_empty() {
        //             measurements = perf_ebpf.read_uj().unwrap();
        //         }
        //         black_box(measurements);
        //     })
        // });
        group.bench_function("math-conversions", |b| {
            b.iter(|| {
                let raw = black_box(123456u64);
                let joules = (raw as f64) * 2.3283064365386962890625e-10;
                let u_joules = (joules * 1000_000.0) as u64;
                black_box(u_joules);
            })
        });
    }
    */
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
