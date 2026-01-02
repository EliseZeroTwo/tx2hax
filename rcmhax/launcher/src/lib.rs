mod device;
mod hax;

pub use device::RcmDevice;
pub use hax::PAYLOAD_LOAD_ADDRESS;

pub fn open_post() -> anyhow::Result<device::RcmDevice> {
    let start = std::time::Instant::now();

    let device = loop {
        let mut devices = match device::get_devices() {
            Ok(devices) => devices,
            Err(why) => {
                eprintln!("Failed to initialise device: {why}");

                if start.elapsed() > std::time::Duration::from_secs(60) {
                    anyhow::bail!("Device not found within 60 seconds");
                }

                std::thread::sleep(std::time::Duration::from_millis(250));
                continue;
            }
        };

        if devices.len() > 1 {
            anyhow::bail!("Too many RCM devices found!");
        }

        let Some(device) = devices.pop() else {
            if start.elapsed() > std::time::Duration::from_secs(60) {
                anyhow::bail!("Device not found within 60 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        };

        break device;
    };

    let uid = device.read_uid()?;
    print!("Reconnected to device ");
    for ch in uid {
        print!("{ch:02X}");
    }
    println!();

    Ok(device)
}

pub fn pwn(payload: &[u8], ep0_offset: Option<u8>) -> anyhow::Result<()> {
    let mut devices = device::get_devices()?;

    if devices.len() > 1 {
        anyhow::bail!("Too many RCM devices found")
    }

    let Some(mut device) = devices.pop() else {
        anyhow::bail!("No RCM devices found");
    };

    let uid = device.read_uid()?;
    print!("Sending {} byte long payload to device ", payload.len());

    for ch in uid {
        print!("{ch:02X}");
    }

    println!();

    hax::hax(&mut device, payload, ep0_offset.map(|x| x as usize))?;

    println!("The payload should now be running!");

    Ok(())
}
