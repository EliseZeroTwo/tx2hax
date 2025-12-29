mod device;
mod hax;

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, bail};
use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    payload: PathBuf,
    /// How many times to poke the control endpoint.
    /// You only need to set this argument if the exploit fails and tells you a value to use
    #[clap(short = 'o', long)]
    ep0_offset: Option<u8>,
    /// Wait for the device to reappear and log what it sends over USB
    #[clap(short = 'w')]
    wait: bool,
}

fn read_payload(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path).context("opening payload")?;

    let len = file
        .metadata()
        .context("fetching payload file metadata")?
        .len();

    if len > hax::PAYLOAD_MAX_LEN as u64 {
        bail!(
            "Payload is too large, {len} bytes when maximum is {} ({} bytes too many)",
            hax::PAYLOAD_MAX_LEN,
            len - hax::PAYLOAD_MAX_LEN as u64
        );
    }

    let mut buffer = Vec::with_capacity(len as usize);
    file.read_to_end(&mut buffer).context("reading payload")?;
    if buffer.len() as u64 != len {
        bail!(
            "Payload size changed? It was {len} bytes when checked but {} bytes were read from disk",
            buffer.len()
        );
    }

    Ok(buffer)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let payload = match read_payload(args.payload.as_path()) {
        Ok(payload) => payload,
        Err(why) => {
            eprintln!("Failed to read payload: {why}");
            return ExitCode::FAILURE;
        }
    };

    let mut devices = match device::get_devices() {
        Ok(devices) => devices,
        Err(why) => {
            eprintln!("{why}");
            return ExitCode::FAILURE;
        }
    };

    if devices.len() > 1 {
        eprintln!("Too many RCM devices found!");
        return ExitCode::FAILURE;
    }

    let Some(mut device) = devices.pop() else {
        eprintln!("No RCM devices found!");
        return ExitCode::FAILURE;
    };

    match device.read_uid() {
        Ok(uid) => {
            print!("Sending {} byte long payload to device ", payload.len());

            for ch in uid {
                print!("{ch:02X}");
            }

            println!();
        }
        Err(why) => {
            eprintln!("{}", why);
            return ExitCode::FAILURE;
        }
    }

    if let Err(why) = hax::hax(&mut device, &payload, args.ep0_offset.map(|x| x as usize)) {
        eprintln!("{}", why);
        return ExitCode::FAILURE;
    }

    println!("The payload should now be running!");

    if args.wait {
        let start = std::time::Instant::now();

        let mut device = loop {
            let mut devices = match device::get_devices() {
                Ok(devices) => devices,
                Err(why) => {
                    eprintln!("Failed to initialise device: {why}");

                    if start.elapsed() > std::time::Duration::from_secs(60) {
                        eprintln!("Device not found within 60 seconds");
                        return ExitCode::FAILURE;
                    }

                    std::thread::sleep(std::time::Duration::from_millis(250));
                    continue;
                }
            };

            if devices.len() > 1 {
                eprintln!("Too many RCM devices found!");
                return ExitCode::FAILURE;
            }

            let Some(device) = devices.pop() else {
                if start.elapsed() > std::time::Duration::from_secs(60) {
                    eprintln!("Device not found within 60 seconds");
                    return ExitCode::FAILURE;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
                continue;
            };

            break device;
        };

        println!(
            "Device alive again after {:.2}s!",
            start.elapsed().as_secs_f64()
        );

        if let Err(why) = hax::post(&mut device) {
            eprintln!("{}", why);
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}
