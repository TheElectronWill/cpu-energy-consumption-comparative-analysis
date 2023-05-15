use std::{
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::Context;
use log::{debug, info};
use regex::Regex;

pub fn run_benchmark(benchmark_type: &str, n_events: usize, n_cores: usize) -> anyhow::Result<Option<SysbenchResults>> {
    // It seems more precise to limit the number of events instead of the running time.
    // The goal "number of events" seems to be always reached perfectly, but the running time slightly varies.

    if benchmark_type == "sleep" {
        // sleep benchmark to check that all the probes work properly
        std::thread::sleep(Duration::from_millis(n_events as u64));
        Ok(None)
    } else {
        let seed = 42421;
        let child = Command::new("sysbench")
            .args([
                benchmark_type,
                "run",
                &format!("--events={n_events}"),
                &format!("--threads={n_cores}"),
                &format!("--rand-seed={seed}"), // set a seed to limit the differences between two runs
                "--time=0",                     // disable the time limit
            ])
            .stdout(Stdio::piped())
            .spawn()?;
        let out = child.wait_with_output()?;
        let stdout = std::str::from_utf8(&out.stdout)?;
        debug!("{stdout}");

        let parsed = parse_sysbench_output(stdout)?;
        Ok(Some(parsed))
    }
}

fn parse_sysbench_output(stdout: &str) -> anyhow::Result<SysbenchResults> {
    let time_re = Regex::new(r"total time:\s+([0-9.]+)s")?;
    let evt_re = Regex::new(r"events per second:\s+([0-9.]+)")?;
    let lat_min = Regex::new(r"min:\s+([0-9.]+)")?;
    let lat_avg = Regex::new(r"avg:\s+([0-9.]+)")?;
    let lat_max = Regex::new(r"max:\s+([0-9.]+)")?;
    let lat_percentile = Regex::new(r"95th percentile:\s+([0-9.]+)")?;
    let lat_sum = Regex::new(r"sum:\s+([0-9.]+)")?;

    fn find_and_parse_float(input: &str, regex: Regex, name: &str) -> anyhow::Result<f32> {
        let captures = regex.captures(input).context(format!("{name} not found"))?;
        let g = captures.get(1).unwrap();
        let parsed = g.as_str().parse().with_context(|| format!("failed to parse{g:?}"))?;
        Ok(parsed)
    }

    let events_per_sec: Option<f32> = if let Some(evt_match) = evt_re.captures(stdout) {
        let g = evt_match.get(1).unwrap();
        let value = g
            .as_str()
            .parse::<f32>()
            .with_context(|| format!("failed to parse events per second {evt_match:?}"))?;
        Some(value)
    } else {
        None
    };

    let total_time = find_and_parse_float(stdout, time_re, "total time")?;
    let latency_min = find_and_parse_float(stdout, lat_min, "latency min")?;
    let latency_max = find_and_parse_float(stdout, lat_max, "latency max")?;
    let latency_avg = find_and_parse_float(stdout, lat_avg, "latency avg")?;
    let latency_percentile = find_and_parse_float(stdout, lat_percentile, "latency percentile")?;
    let latency_sum = find_and_parse_float(stdout, lat_sum, "latency sum")?;

    Ok(SysbenchResults {
        total_time,
        events_per_sec,
        latency_min,
        latency_avg,
        latency_max,
        latency_percentile,
        latency_sum,
    })
}

#[derive(Debug)]
pub struct SysbenchResults {
    /// The total execution time, in seconds
    pub total_time: f32,

    /// Avg events per second
    pub events_per_sec: Option<f32>,

    /// Latency info
    pub latency_min: f32,
    pub latency_max: f32,
    pub latency_avg: f32,
    pub latency_sum: f32,
    pub latency_percentile: f32,
}

#[cfg(test)]
mod tests {
    use super::parse_sysbench_output;

    #[test]
    fn test_parse_sysbench() {
        let example = "
    Threads started!

    CPU speed:
        events per second:   228.80

    General statistics:
        total time:                          0.0016s
        total number of events:              1

    Latency (ms):
             min:                                    1.52
             avg:                                    1.52
             max:                                    1.52
             95th percentile:                        1.52
             sum:                                    1.52

    Threads fairness:
        events (avg/stddev):           1.0000/0.00
        execution time (avg/stddev):   0.0015/0.00
";
        let res = parse_sysbench_output(example).unwrap();
        assert_eq!(res.total_time, 0.0016);
        assert_eq!(res.events_per_sec, Some(228.80));

        let not_cpu = "
    Threads started!

    General statistics:
        total time:                          0.0713s
        total number of events:              1000

    Latency (ms):
             min:                                    1.01
             avg:                                    2.02
             max:                                    3.03
             95th percentile:                        4.04
             sum:                                    5.05

    Threads fairness:
        events (avg/stddev):           1.0000/0.00
        execution time (avg/stddev):   0.0015/0.00
";
        let res = parse_sysbench_output(not_cpu).unwrap();
        assert_eq!(res.total_time, 0.0713);
        assert_eq!(res.events_per_sec, None);
        assert_eq!(res.latency_min, 1.01);
        assert_eq!(res.latency_avg, 2.02);
        assert_eq!(res.latency_max, 3.03);
        assert_eq!(res.latency_percentile, 4.04);
        assert_eq!(res.latency_sum, 5.05);
    }
}
