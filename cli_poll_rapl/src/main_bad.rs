use super::main_optimized::print_measurements as print_measurements_message;
use super::main_optimized::MeasurementsMessage;

use rapl_probes::{EnergyMeasurements, EnergyProbe};

use anyhow::Context;
use std::io::Write;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc::{self, Sender};

#[cfg(feature = "bad_sleep_singlethread")]
pub fn run_bad_sleep_singlethread(
    mut writer: Box<dyn Write + Send>,
    mut probe: Box<dyn EnergyProbe>,
    polling_period: Duration,
    measurement_flush_interval: Duration,
) -> anyhow::Result<()> {
    let mut previous_timestamp: SystemTime = SystemTime::now();

    // write the csv header
    writer.write("timestamp_ms;socket;domain;overflow;joules\n".as_bytes())?;

    loop {
        // wait for the polling period, CAVEAT: actually, this is very unprecise
        std::thread::sleep(polling_period);

        probe.poll().context("refreshing measurements")?;
        let m = probe.measurements();

        let timestamp = SystemTime::now();
        print_measurements_direct(&mut writer, &m, timestamp)?;

        let time_since_last_flush = timestamp.duration_since(previous_timestamp).unwrap_or(Duration::ZERO);
        if time_since_last_flush >= measurement_flush_interval {
            previous_timestamp = timestamp;
            writer.flush()?;
        }
    }
}

#[cfg(feature = "bad_sleep")]
pub async fn run_bad_sleep(
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
            print_measurements_message(&mut writer, &msg)?;

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
    poll_energy_probe_badly(probe.as_mut(), polling_period, tx)
        .await
        .expect("probe error");

    handle.await?.expect("writer task error");

    Ok(())
}

async fn poll_energy_probe_badly(
    probe: &mut dyn EnergyProbe,
    period: Duration,
    tx: Sender<MeasurementsMessage>,
) -> anyhow::Result<()> {
    loop {
        // wait for the next period
        std::thread::sleep(period);

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

fn print_measurements_direct(writer: &mut dyn Write, m: &EnergyMeasurements, t: SystemTime) -> anyhow::Result<()> {
    let timestamp_ms = t.duration_since(SystemTime::UNIX_EPOCH)?.as_millis();

    for (socket_id, domains_of_socket) in m.per_socket.iter().enumerate() {
        for (domain, counter) in domains_of_socket {
            if let Some(consumed) = counter.joules {
                let overflow = counter.overflowed;
                writeln!(writer, "{timestamp_ms};{socket_id};{domain:?};{overflow};{consumed}")?;
            }
        }
    }
    Ok(())
}
