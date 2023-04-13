pub mod ebpf;
pub mod perf_rapl;
pub mod powercap;

pub trait Probe: Send {
    /// Reads the current value of the probe, in **microJoules**.
    fn read_uj(&mut self) -> anyhow::Result<Vec<EnergyMeasurement>>;
}

#[derive(Debug)]
pub struct EnergyMeasurement {
    /// The energy **counter**, in microjoules.
    /// This counter is modified by RAPL, and can overflow.
    /// If you need the energy consumed by a task,
    /// you need to measure before and after the task:
    ///
    /// ```
    /// let before = probe.read_uj();
    /// run_task();
    /// let after = probe.read_uj();
    /// let consumed_energy = after.energy_counter - before.energy_counter;
    /// println!("Task consumed {consumed_energy} microJoules");
    /// ```
    pub energy_counter: u64,

    /// The logical cpu number (0-N where N is the number of _cores_ on the machine).
    pub cpu: u32,
}
