use anyhow::{Context, Result, anyhow, bail};
use rusb::{Device, DeviceHandle, GlobalContext, TransferType};

const RCM_VID: u16 = 0x0955;
const RCM_PRODUCT: &str = "APX";
const RCM_MANUFACTURER: &str = "NVIDIA Corp.";

const TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(4);
const TIMEOUT_DURATION_SMALL: std::time::Duration = std::time::Duration::from_millis(750);

const BASE_ADDR: u32 = 0x4001fa50;

pub struct RcmDevice {
    handle: DeviceHandle<GlobalContext>,
    in_endpoint: u8,
    out_endpoint: u8,

    bytes_written: u64,
}

impl RcmDevice {
    pub fn init_if_rcm(device: Device<GlobalContext>) -> Result<Option<Self>> {
        let device_descriptor = device
            .device_descriptor()
            .map_err(|why| anyhow!("Failed to fetch USB device descriptor: {why}"))?;

        tracing::debug!(
            "Inspecting device: Bus {:03} Device {:03} ID {:04x}:{:04x}",
            device.bus_number(),
            device.address(),
            device_descriptor.vendor_id(),
            device_descriptor.product_id(),
        );

        if device_descriptor.vendor_id() != RCM_VID {
            tracing::debug!("VID mismatch");
            return Ok(None);
        }

        let config_descriptor = device
            .active_config_descriptor()
            .context("Failed to fetch USB config descriptor")?;

        let handle = device.open().context("Failed to open USB device")?;

        let product = handle
            .read_product_string_ascii(&device_descriptor)
            .context("Failed to read product string")?;

        if product.as_str() != RCM_PRODUCT {
            tracing::debug!("Product mismatch ('{product}' != '{RCM_PRODUCT}')");
            return Ok(None);
        }

        let manufacturer = handle
            .read_manufacturer_string_ascii(&device_descriptor)
            .context("Failed to read manufacturer string")?;

        if manufacturer.as_str() != RCM_MANUFACTURER {
            tracing::debug!("Manufacturer mismatch ('{manufacturer}' != '{RCM_MANUFACTURER}')");
            return Ok(None);
        }

        // Any error or missing component from here should be treated as an error rather than an unrecognised device as the device reported itself as an RCM device

        handle.reset().context("Failed to reset USB device")?;
        handle
            .set_active_configuration(config_descriptor.number())
            .context("Failed to set active configuration for USB device")?;

        let mut found_interface = false;
        let mut endpoints = (None, None);
        'outer: for interface in config_descriptor.interfaces() {
            for descriptor in interface.descriptors() {
                if descriptor.class_code() == 0xFF
                    && descriptor.sub_class_code() == 0xFF
                    && descriptor.num_endpoints() == 2
                {
                    found_interface = true;

                    handle
                        .claim_interface(interface.number())
                        .context("Failed to claim RCM interface")?;
                    handle
                        .set_alternate_setting(interface.number(), descriptor.setting_number())
                        .context("Failed to set RCM interface alternate setting")?;

                    for endpoint in descriptor.endpoint_descriptors() {
                        if endpoint.transfer_type() == TransferType::Bulk {
                            match endpoint.direction() {
                                rusb::Direction::In => {
                                    tracing::debug!(
                                        "Found bulk in endpoint: {}",
                                        endpoint.address()
                                    );
                                    endpoints.0 = Some(endpoint.address());
                                }
                                rusb::Direction::Out => {
                                    tracing::debug!(
                                        "Found bulk out endpoint: {}",
                                        endpoint.address()
                                    );
                                    endpoints.1 = Some(endpoint.address());
                                }
                            }
                        }
                    }

                    break 'outer;
                }
            }
        }

        if !found_interface {
            bail!("Failed to find RCM interface");
        }

        let (Some(in_endpoint), Some(out_endpoint)) = endpoints else {
            bail!("Failed to find bulk endpoints on RCM interface");
        };

        Ok(Some(Self {
            handle,
            in_endpoint,
            out_endpoint,
            bytes_written: 0,
        }))
    }

    pub const fn current_address(&self) -> u32 {
        BASE_ADDR.wrapping_add(self.bytes_written as u32)
    }

    fn write_raw(&self, data: &[u8]) -> Result<()> {
        tracing::trace!("Writing {data:02x?}");

        let amount = self
            .handle
            .write_bulk(self.out_endpoint, data, TIMEOUT_DURATION)
            .context("Failed to write data to device")?;

        if amount != data.len() {
            bail!("Device only accepted {amount} out of {} bytes", data.len());
        }

        Ok(())
    }

    pub fn read_no_timeout(&self, buffer: &mut [u8]) -> Result<usize> {
        let amt = self
            .handle
            .read_bulk(self.in_endpoint, buffer, std::time::Duration::MAX)
            .context("Failed to read data from device")?;

        tracing::trace!("Read {:02x?}", &buffer[..amt]);
        Ok(amt)
    }

    pub fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        let amt = self
            .handle
            .read_bulk(self.in_endpoint, buffer, TIMEOUT_DURATION)
            .context("Failed to read data from device")?;

        tracing::trace!("Read {:02x?}", &buffer[..amt]);
        Ok(amt)
    }

    pub fn read_uid(&self) -> Result<[u8; 0x10]> {
        let mut uid = [0u8; 0x10];

        tracing::debug!("Reading UID");
        let read = self.read(&mut uid)?;
        if read != 0x10 {
            bail!("Device sent only {read} out of 16 bytes when sending it's UID");
        }
        Ok(uid)
    }

    pub fn write_until(&mut self, target: u32) -> Result<()> {
        self.write_length(target.wrapping_sub(self.current_address()) as usize)
    }

    pub fn write(&mut self, buffer: &[u8]) -> Result<()> {
        self.write_raw(buffer)?;
        self.bytes_written += buffer.len() as u64;
        Ok(())
    }

    pub fn write_length(&mut self, len: usize) -> Result<()> {
        const BUFFER: &[u8] = &[0u8; 64 * 1024 * 32];

        let pb = (len > 1024 * 1024 * 32).then(|| {
            let pb = indicatif::ProgressBar::new(len as u64);
            pb.set_style(
                indicatif::ProgressStyle::with_template(
                    "[{elapsed_precise}] [{wide_bar}] {bytes}/{total_bytes} ({eta})",
                )
                .unwrap()
                .with_key(
                    "eta",
                    |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                        write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                    },
                )
                .progress_chars("#>-"),
            );
            pb
        });

        let mut remaining_to_write = len;
        let mut amt_read = 0u64;
        while remaining_to_write != 0 {
            let iter_amt = BUFFER.len().min(remaining_to_write);

            self.write(&BUFFER[..iter_amt])?;

            remaining_to_write -= iter_amt;
            amt_read += iter_amt as u64;

            if let Some(pb) = pb.as_ref() {
                pb.set_position(amt_read);
            }
        }

        if let Some(pb) = pb.as_ref() {
            pb.finish_and_clear();
        }

        Ok(())
    }

    pub fn log_written(&self, what: &str) {
        tracing::debug!(
            "Written {what}! (addr={:#010X}) (written_bytes={:#X})",
            self.current_address(),
            self.bytes_written
        );
    }

    pub fn bump_ep0_ring(&self) -> Result<()> {
        let mut buf = [0u8; 1];
        self.handle.read_control(
            rusb::request_type(
                rusb::Direction::In,
                rusb::RequestType::Standard,
                rusb::Recipient::Interface,
            ),
            0,
            0,
            0,
            &mut buf,
            TIMEOUT_DURATION_SMALL,
        )?;
        Ok(())
    }

    pub fn bump_ep1_out_ring(&self) -> anyhow::Result<()> {
        self.write_raw(&[])
    }

    pub fn unstall_ep1_out(&self) -> Result<()> {
        self.handle.write_control(
            rusb::request_type(
                rusb::Direction::Out,
                rusb::RequestType::Standard,
                rusb::Recipient::Endpoint,
            ),
            1,
            0,
            1,
            &[],
            TIMEOUT_DURATION_SMALL,
        )?;

        Ok(())
    }

    pub fn do_svc(&self) -> Result<()> {
        let mut buf = [0u8; 0x12];
        self.handle.read_control(
            rusb::request_type(
                rusb::Direction::In,
                rusb::RequestType::Standard,
                rusb::Recipient::Device,
            ),
            6,
            1 << 8 | 1, // ORing by 1 is 'invalid' here but it is ignored by the TX2 whilst bypassing Darwin's caching of this request type
            0,
            &mut buf,
            TIMEOUT_DURATION_SMALL,
        )?;

        Ok(())
    }

    pub fn send_link_trb(&mut self, link_addr: u32) -> Result<()> {
        assert_eq!(link_addr & 0xf, 0);
        let mut trb = [0u8; 0x10];
        trb[0..4].copy_from_slice(&link_addr.to_le_bytes());
        trb[12..].copy_from_slice(&0x1803u32.to_le_bytes());
        self.write(&trb)?;
        Ok(())
    }
}

pub fn get_devices() -> anyhow::Result<Vec<RcmDevice>> {
    let mut devices = Vec::new();

    let raw_devices =
        rusb::devices().map_err(|why| anyhow!("Failed to iterate over USB devices: {why}"))?;

    for device in raw_devices.iter() {
        let device = match RcmDevice::init_if_rcm(device) {
            Ok(Some(device)) => device,
            Ok(None) => continue,
            Err(why) => {
                tracing::debug!("Error when initialising device: {why}");
                continue;
            }
        };

        tracing::debug!("Found an RCM device");

        devices.push(device);
    }

    Ok(devices)
}

#[macro_export]
macro_rules! bump {
    ($device:expr => ep1 * $amt:literal) => {
        for idx in 0..$amt {
            println!("Bump attempt {idx}");
            $device.bump_ep1_ring()?;
        }
    };

    ($device:expr => ep0 * $amt:literal) => {
        for idx in 0..$amt {
            if $device.fetch_ctrl().is_err() {
                println!("Control poke failed on idx={idx}");
                break;
            };
            println!("Ctrl poke idx={idx}");
        }
    };
}
