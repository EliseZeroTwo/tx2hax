#[cfg(feature = "sehax")]
mod sehax;

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, bail};
use clap::Parser;
#[cfg(feature = "sehax")]
use sha2::Digest;

const PAYLOAD_MAX_LEN: usize = 0x4005_0000 - rcmhax_launcher::PAYLOAD_LOAD_ADDRESS;

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
    /// Wait for the device to reappear and do sehax on the output
    #[cfg(feature = "sehax")]
    #[clap(short = 's')]
    sehax: bool,
}

fn read_payload(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path).context("opening payload")?;

    let len = file
        .metadata()
        .context("fetching payload file metadata")?
        .len();

    if len > PAYLOAD_MAX_LEN as u64 {
        bail!(
            "Payload is too large, {len} bytes when maximum is {} ({} bytes too many)",
            PAYLOAD_MAX_LEN,
            len - PAYLOAD_MAX_LEN as u64
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

pub fn post(device: &mut rcmhax_launcher::RcmDevice) -> anyhow::Result<()> {
    println!("-- USB Logs --");

    let mut buffer = [0u8; 0x10000];
    loop {
        let len = match device.read_no_timeout(&mut buffer) {
            Ok(len) => len,
            Err(why) => {
                tracing::warn!("Device exited from logging: {why}");
                return Ok(());
            }
        };
        for &ch in &buffer[..len] {
            if ch == b'\n' || ch == b'\r' || (0x20..0x7F).contains(&ch) {
                std::io::stdout().write_all(&[ch]).unwrap();
            } else {
                print!("\\x{ch:02X}");
            }
        }
    }
}

#[cfg(feature = "sehax")]
pub fn sehax_post(device: &mut rcmhax_launcher::RcmDevice) -> anyhow::Result<()> {
    let mut buffer = [0u8; 0x10000];
    let mut read = 0;
    while read < 0x40 {
        let len = match device.read_no_timeout(&mut buffer[read..]) {
            Ok(len) => len,
            Err(why) => {
                anyhow::bail!("Device exited from sehax with {read} read: {why}");
            }
        };
        read += len;
    }

    let mut vector_0123 = [0u8; 0x10];
    let mut vector_012 = [0u8; 0x10];
    let mut vector_01 = [0u8; 0x10];
    let mut vector_0 = [0u8; 0x10];
    vector_0123.copy_from_slice(&buffer[..0x10]);
    vector_012.copy_from_slice(&buffer[0x10..0x20]);
    vector_01.copy_from_slice(&buffer[0x20..0x30]);
    vector_0.copy_from_slice(&buffer[0x30..0x40]);
    let Some(key) = sehax::sehax(&vector_0123, &vector_012, &vector_01, &vector_0) else {
        anyhow::bail!("Failed to recover key");
    };

    print!("Key: ");
    for item in &key {
        print!("{item:02X}")
    }
    println!();

    let hash = sha2::Sha256::digest(&key);

    print!("SHA256(Key): ");
    for item in &hash {
        print!("{item:02X}")
    }
    println!();

    Ok(())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    #[cfg(feature = "sehax")]
    if args.sehax && args.wait {
        eprintln!("Cannot pass both -s and -w");
        return ExitCode::FAILURE;
    }

    let payload = match read_payload(args.payload.as_path()) {
        Ok(payload) => payload,
        Err(why) => {
            eprintln!("Failed to read payload: {why}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(why) = rcmhax_launcher::pwn(&payload, args.ep0_offset) {
        eprintln!("{why}");
        return ExitCode::FAILURE;
    }

    if args.wait {
        match rcmhax_launcher::open_post() {
            Ok(mut device) => {
                if let Err(why) = post(&mut device) {
                    eprintln!("{}", why);
                    return ExitCode::FAILURE;
                }
            }
            Err(why) => {
                eprintln!("{}", why);
                return ExitCode::FAILURE;
            }
        };
    }

    #[cfg(feature = "sehax")]
    if args.sehax {
        match rcmhax_launcher::open_post() {
            Ok(mut device) => {
                if let Err(why) = sehax_post(&mut device) {
                    eprintln!("{}", why);
                    return ExitCode::FAILURE;
                }
            }
            Err(why) => {
                eprintln!("{}", why);
                return ExitCode::FAILURE;
            }
        };
    }

    ExitCode::SUCCESS
}
