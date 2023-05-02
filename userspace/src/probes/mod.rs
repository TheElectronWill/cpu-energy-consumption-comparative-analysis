pub mod ebpf;
pub mod msr;
pub mod perf_rapl;
pub mod powercap;

/// An energy counter that can be read.
pub trait EnergyCounter: Send {
    /// Returns the current value of the energy counter.
    /// This method does **not** apply any conversion.
    fn read(&self) -> anyhow::Result<u64>;
}

pub struct EnergyProbe<C> {
    counter: C,
    previous_value: Option<u64>,
    energy_unit: f64,
}

impl<C: EnergyCounter> EnergyProbe<C> {
    /// Creates a new `EnergyProbe`.
    ///
    /// `counter_value * energy_unit = Joules`
    pub fn new(counter: C, energy_unit: f64) -> EnergyProbe<C> {
        EnergyProbe {
            counter,
            previous_value: None,
            energy_unit,
        }
    }

    /// Returns the number of Joules consumed since the last call,
    /// based on the underlying energy counter, and a flag that indicates
    /// whether an overflow has occured (`true` means overflow, `false` means no overflow).
    ///
    /// If this is the first call, returns `None`.
    ///
    /// ## Usage
    ///
    /// ```ignore
    /// if let Some((joules, overflow)) = probe.read_consumed_joules() {
    ///     println!("{joules} J consumed");
    /// }
    ///
    /// ```
    ///
    /// ## Overflows
    ///
    /// RAPL counters overflow after some time, which depends on the consumption
    /// of the monitored domain. This time can be lower than one minute.
    /// To avoid losing data and reporting wrong measurements, no more than one overflow
    /// must occur between two measurements. That is, the polling frequency must be high enough.
    ///
    /// If two consecutive calls return `true`, then the frequency is either too low,
    /// or barely right (but that's risky).
    ///
    pub fn read_consumed_joules(&self) -> Option<(f64, bool)> {
        let current = self.counter.read();
        let res = {
            if let Some(prev) = self.previous_value {
                if current < prev {
                    // one or more overflow have occured, we cannot know how many,
                    // so we assume it was only one.
                    let corrected = u64::MAX - prev + current;
                    Some((corrected * self.energy_unit, true))
                } else {
                    let diff = current - prev;
                    Some((diff * self.energy_unit, false))
                }
            } else {
                None
            }
        };
        self.previous_value = Some(current);
        res
    }

    // NOTE: the energy_counter can be a floating-point number in Joules,
    // without any loss of precision. Why? Because multiplying any number
    // by a float that is a power of two will only change the "exponent" part,
    // not the "mantissa".
    //
    // A f32 can hold integers without any precision loss
    // up to approximately 2^24, which is not enough for the RAPL counter values,
    // so we use a f64 here.
}
