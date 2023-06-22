use std::{fmt::Display, str::FromStr};

use clap::{Parser, Subcommand, ValueEnum};
use rapl_probes::RaplDomainType;

#[derive(Parser)]
#[command(author, version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Only show info about CPU and RAPL domains, then exit.
    Info,

    /// Poll some RAPL domains continuously
    Poll {
        /// How to access RAPL counters.
        #[arg(value_enum)]
        probe: ProbeType,

        /// The RAPL domains to record.
        #[arg(short, long, value_delimiter = ',', required = true)]
        domains: Vec<RaplDomainType>,

        /// Measurement frequency, in Hertz.
        #[arg(short, long)]
        frequency: i64,

        /// Print energy measurements on each iteration.
        #[arg(short, long, value_enum)]
        output: OutputType,
        
        /// Sets the output file, if output if set to file.
        #[arg(long)]
        output_file: Option<String>,
    },
}

#[derive(Clone, ValueEnum, Debug, PartialEq, Eq, Copy)]
pub enum OutputType {
    None,
    Stdout,
    File,
}

impl Display for OutputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (self as &dyn std::fmt::Debug).fmt(f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeType {
    PowercapSysfs,
    PerfEvent,
    Ebpf,
    Msr,
}

impl Display for ProbeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ProbeType::PowercapSysfs => "powercap-sysfs",
            ProbeType::PerfEvent => "perf-event",
            ProbeType::Ebpf => "ebpf",
            ProbeType::Msr => "msr",
        };
        f.write_str(str)
    }
}

impl FromStr for ProbeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "powercap" | "powercap-sysfs" => Ok(ProbeType::PowercapSysfs),
            "perf" | "perf-event" => Ok(ProbeType::PerfEvent),
            "ebpf" | "bpf" => Ok(ProbeType::Ebpf),
            "msr" => Ok(ProbeType::Msr),
            _ => Err(s.to_owned()),
        }
    }
}
