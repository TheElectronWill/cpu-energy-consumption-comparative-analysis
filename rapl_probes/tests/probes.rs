// use userspace::probes::{EnergyProbe, EnergyCounter};


// // #[test]
// fn general_1() {
//     let probe: &dyn EnergyProbe = todo!();
//     let a = probe.read();
//     // ...
//     let b = probe.read();
//     let (diff, overflow) = (b-a)*probe.unit();
// }

// fn general_2() {
//     let probe: &dyn EnergyProbe = todo!();
//     let a = probe.read();
//     // ...
//     let b = probe.read();
//     let (diff, overflow) = probe.joules_diff(a, b);
// }

// fn multiple_1() {
//     struct PerfEventProbe { unit: f32 }
//     struct ProbeHistory<P> { probe: P, previous: Option<EnergyCounter> }
//     // et pk pas:
//     // impl ProbeHistory {
//     //   /// Poll the current value and return the difference with the previous value, if any
//     //   fn poll_diff(&self) -> Option<(f64, bool)>
//     // }
    
//     // ou juste en fait:
//     // trait Probe {
//     //   fn poll_diff(&self) -> Option<(f64, bool)>    
//     // }

//     let probes: Vec<ProbeHistory<PerfEventProbe>> = todo!();
//     for p in probes {
//         if let Some(prev) = p.previous {
//             let (diff_raw, overflow) = cur-prev;
//             let diff_joules = diff_raw * p.probe.unit;
//         }
//     }
// }
