use rapl_probes::{EnergyMeasurements, EnergyProbe};

use anyhow::Context;
use futures::stream::StreamExt;
use std::io::Write;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc::{self, Sender};
use tokio_timerfd::Interval;

pub async fn run(
    mut writer: Box<dyn Write + Send>,
    mut probe: Box<dyn EnergyProbe>,
    polling_period: Duration,
    measurement_flush_interval: Duration,
) -> anyhow::Result<()> {
    // open a Channel to write to the output in another thread
    let (tx, mut rx) = mpsc::channel::<MeasurementsMessage>(4096);

    // Start the writer task, which will receive the data from the channel and write
    // it to the selected output.
    let handle = tokio::spawn(async move {
        let mut previous_timestamp: SystemTime = SystemTime::now();

        // write the csv header
        writer.write("timestamp_ms;socket;domain;overflow;joules\n".as_bytes())?;
        while let Some(msg) = rx.recv().await {
            print_measurements(&mut writer, &msg)?;

            let time_since_last_flush = msg
                .timestamp
                .duration_since(previous_timestamp)
                .unwrap_or(Duration::ZERO);

            if time_since_last_flush >= measurement_flush_interval {
                previous_timestamp = msg.timestamp;
                writer.flush()?;
            }
        }

        anyhow::Ok(())
    });

    // Start the polling task, which will poll the RAPL counters at regular intervals
    // and send the data to the writer task, through the channel.
    poll_energy_probe(probe.as_mut(), polling_period, tx)
        .await
        .expect("probe error");

    handle.await?.expect("writer task error");

    Ok(())
}

#[derive(Debug)]
pub(crate) struct MeasurementsMessage {
    pub timestamp: SystemTime,
    pub measurements: EnergyMeasurements,
}

async fn poll_energy_probe(
    probe: &mut dyn EnergyProbe,
    period: Duration,
    tx: Sender<MeasurementsMessage>,
) -> anyhow::Result<()> {
    // Underneath, this uses a periodic timer from timerfd, which has a higher resolution than std::time::sleep and tokio::time::sleep
    // Also, using an interval is better than using a `Delay` by hand
    // (for 1000Hz, we get close to 999Hz with the Interval but only around 860Hz with the Delay).
    let mut interval = Interval::new_interval(period)?;

    loop {
        // wait for the next tick of the periodic timer
        interval.next().await;

        // poll the new values from the probe
        probe.poll().context("refreshing measurements")?;
        let m = probe.measurements();

        // // send the values to the writer task through the channel
        let timestamp = SystemTime::now();
        let measurements = m.clone();

        tx.send(MeasurementsMessage {
            timestamp,
            measurements,
        })
        .await
        .expect("failed to send measurement through channel");
    }
}

pub(crate) fn print_measurements(writer: &mut dyn Write, msg: &MeasurementsMessage) -> anyhow::Result<()> {
    let timestamp_ms = msg.timestamp.duration_since(SystemTime::UNIX_EPOCH)?.as_millis();

    for (socket_id, domains_of_socket) in msg.measurements.per_socket.iter().enumerate() {
        for (domain, counter) in domains_of_socket {
            if let Some(consumed) = counter.joules {
                let overflow = counter.overflowed;
                writeln!(writer, "{timestamp_ms};{socket_id};{domain:?};{overflow};{consumed}")?;
            }
        }
    }
    Ok(())
}
