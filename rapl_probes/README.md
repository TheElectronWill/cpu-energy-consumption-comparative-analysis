# Implementation of RAPL probes

## MSR

RAPL is exposed through Model Specific Registers, or MSR.
These registers are documented in the _Intel Software Developer Manual, volume 3B_, chapter _Power and Thermal Management_, section _15.10.1 - RAPL interfaces_.

The 64 bits register `MSR_RAPL_POWER_UNIT` gives the units of the RAPL counters. The value that we're interested in is _Energy Status Unit_ or `ESU`, which is stored in bits 12 à 8 of `MSR_RAPL_POWER_UNIT`.

Then, we can read bits 31 à 0 of the following registers :
- `MSR_PKG_ENERGY_STATUS`
- `MSR_PP0_ENERGY_STATUS`
- `MSR_PP1_ENERGY_STATUS`
- `MSR_DRAM_ENERGY_STATUS`
- `MSR_PLATFORM_ENERGY_STATUS`

### Energy computation and overflow

Each register is a cumulative counter of the consumed energy. The unit is `(1/2)^ESU` Joules.

$\text{msr\_to\_joules}(m) = m \times 0.5^{ESU}$

The CPU adds its consumption to the counter every 0.976 milliseconds. The counter _will_ therefore overflow after a given amount of time, which depends on the RAPL domain's consumption. This can happen quickly! The manual gives a hint of approximately 60 seconds "during heavy consumption".

The overflow needs to be corrected :
$$
\Delta m =
\begin{cases}
  \text{u32::max} - m_{prev} + m_{current} &\text{si}\ m_{current} < m_{prev} \\
  m_{current} - m_{prev} &\text{sinon} \\
\end{cases}
$$

### Beware of the measurement

Since the counter is cumulative, one value is not meaningful, we need to compute the difference between two values. This applies to all interfaces that provide the RAPL energy counters.

## Perf event interface

Linux provides the "performance events" interface, which gives access - among other things - to the CPU performance counters, including RAPL registers.

A description of the events that correspond to the RAPL registers can be found in `/sys/devices/power/events/`, which contains 3 files per event, one event per RAPL domain. Example:

- energy-cores
- energy-cores.scale
- energy-cores.unit
- energy-gpu
- energy-gpu.scale
- energy-gpu.unit
- energy-pkg
- energy-pkg.scale
- energy-pkg.unit
- energy-psys
- energy-psys.scale
- energy-psys.unit
- energy-ram
- energy-ram.scale
- energy-ram.unit

For the `core` domain, we have:
- `energy-cores`: contains the id of the perf events, for instance `event=0x02`
- `energy-cores.scale`: contains the factor to apply to the values returned by perf-events in order to get Joules
- `energy-cores.unit`: tells that the values, after scaling, are in `Joules`

To read the registers with `perf_event`, the corresponding events need to be opened with [`perf_event_open`](https://man7.org/linux/man-pages/man2/perf_event_open.2.html). The "pmu type" argument can change depending on the hardware and kernel version, it is given by reading `/sys/devices/power/type`.

### Energy computation and overflow

The perf_event interface [already deals with overflow](https://github.com/torvalds/linux/blob/921bdc72a0d68977092d6a64855a1b8967acc1d9/arch/x86/events/rapl.c#LL200C2-L200C2). Out experiments confirm that the returned value is a [64 bits integer](https://lwn.net/Articles/573602/).

That integer could still overflow (but very rarely), and the following correction can be applied:
$$
\Delta m =
\begin{cases}
  \text{u64::max} - m_{prev} + m_{current} &\text{si}\ m_{current} < m_{prev} \\
  m_{current} - m_{prev} &\text{sinon} \\
\end{cases}
$$

## Powercap

Power zones hierarchy is described in the sysfs directory `/sys/devices/virtual/powercap/intel-rapl`.
Each zone corresponds to a RAPL domain.

Example:
```
intel-rapl
  |
  |--- intel-rapl:0
  |     |--- intel-rapl:0:0
  |     |--- intel-rapl:0:1
  |     |--- intel-rapl:0:2
  |
  |--- intel-rapl:1
```

For each zone, we have the following information:
- `name` : name of the zone, in one of the following formats.
    - `package-N` where N is the package number (socket)
    - `psys` : "Platform" RAPL domain
    - `core` : "Power Plane 0" RAPL domain
    - `uncore` : "Power Plane 1" RAPL domain
    - `dram`
- `energy_uj` : current value of the energy counter, in **microJoules**
- `max_energy_uj` : maximum value of the counter before overflow, thereafter $max_e$ .

### Energy computation and overflow

The powercap counter is computed from the MSR counter, converted to Joules with the "right unit" ([selected based on the domain and hardware](https://github.com/torvalds/linux/blob/9e87b63ed37e202c77aa17d4112da6ae0c7c097c/drivers/powercap/intel_rapl_common.c#L167)).

$e_{uj} = \text{msr\_to\_joules}(m) \times 1000$

Each overflow of the MSR counter $m$ triggers an overflow of the powercap counter $e_{uj}$.

Overflow correction:
$$
\Delta e_{uj} =
\begin{cases}
  max_{e} - e_{prev} + e_{current} &\text{si}\ e_{current} < e_{prev} \\
  e_{current} - e_{prev} &\text{sinon} \\
\end{cases}
$$
