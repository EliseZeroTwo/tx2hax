use core::str;

use rusb::{Device, DeviceHandle, GlobalContext, TransferType};

const FASTBOOT_PRODUCT: &str = "Fastboot";

const FASTBOOT_INTERFACE_CLASS: u8 = 0xFF;
const FASTBOOT_INTERFACE_SUBCLASS: u8 = 0x42;

const TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(4);

/// Defines the maximum packet size types based on the USB connection type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastbootMaxPacketSize {
    /// "Full Speed" USB with a max packet size of 64 bytes
    Full,
    /// "High Speed" USB with a max packet size of 512 bytes
    High,
    /// "Super Speed" USB with a max packet size of 1024 bytes
    Super,
}

impl FastbootMaxPacketSize {
    pub const fn bytes(self) -> usize {
        match self {
            FastbootMaxPacketSize::Full => 64,
            FastbootMaxPacketSize::High => 512,
            FastbootMaxPacketSize::Super => 1024,
        }
    }
}

pub struct FastbootDevice {
    handle: DeviceHandle<GlobalContext>,
    manufacturer: Option<String>,
    serial: String,
    in_endpoint: u8,
    out_endpoint: u8,
    max_packet_size: FastbootMaxPacketSize,
}

#[derive(Debug, thiserror::Error)]
pub enum FastbootDeviceInitError {
    #[error("Failed to fetch USB device descriptor: {0}")]
    GetDeviceDescriptor(rusb::Error),
    #[error("Failed to fetch USB config descriptor: {0}")]
    GetConfigDescriptor(rusb::Error),
    #[error("Failed to open USB device: {0}")]
    Open(rusb::Error),
    #[error("Failed to read product string: {0}")]
    Product(rusb::Error),
    #[error("Failed to read serial number string: {0}")]
    Serial(rusb::Error),
    #[error("Failed to find Fastboot interface")]
    MissingInterface,
    #[error("Failed to reset USB device: {0}")]
    Reset(rusb::Error),
    #[error("Failed to set active configuration for USB device: {0}")]
    SetActiveConfiguration(rusb::Error),
    #[error("Failed to claim Fastboot interface: {0}")]
    ClaimInterface(rusb::Error),
    #[error("Failed to set Fastboot interface alternate setting: {0}")]
    AlternateSetting(rusb::Error),
    #[error("Fastboot interface had '{0}' endpoint(s), expected 2 endpoints (in, out)")]
    InterfaceWrongEndpointCount(u8),
    #[error("Fastboot interface was missing an interface (direction: in, type: bulk)")]
    InterfaceMissingBulkInEndpoint,
    #[error("Fastboot interface was missing an interface (direction: out, type: bulk)")]
    InterfaceMissingBulkOutEndpoint,
    #[error("Fastboot interface was missing both interfaces (directions: in & out, type: bulk)")]
    InterfaceMissingBulkEndpoints,
    #[error("Fastboot device is connected at an invalid device speed: {0:?}")]
    InvalidDeviceSpeed(rusb::Speed),
}

#[derive(Debug, thiserror::Error)]
pub enum FastbootDeviceRuntimeError {
    #[error("Command of length '{0}' was too long, maximum length is 64")]
    CommandTooLong(usize),
    #[error("Command contained non ASCII characters")]
    CommandNonAscii,
    #[error("Error whilst sending packet: {0}")]
    Write(rusb::Error),
    #[error("Error whilst receiving packet: {0}")]
    Read(rusb::Error),
    #[error("Device only accepted {0}/{1} bytes whilst sending packet")]
    WriteTooSmall(usize, usize),
    #[error("Device did not respond with full response type")]
    ReadTypeTooSmall,
    #[error("Device responded with invalid response type")]
    InvalidResponseType,
    #[error("INFO response message contained invalid ASCII")]
    ResponseInfoInvalidAscii,
    #[error("OKAY response message contained invalid ASCII")]
    ResponseOkInvalidAscii,
    #[error("FAIL response message contained invalid ASCII")]
    ResponseFailInvalidAscii,
    #[error("DATA response was '{0}' bytes long, expected 12 bytes")]
    ResponseDataInvalidSize(usize),
    #[error("DATA response message missing valid 8 digit hex number")]
    ResponseDataInvalidNumber,
    #[error("Device reported an error message: '{0}'")]
    Fail(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SendCommandResponse {
    Fail(String),
    Ok(String),
    Data(u32),
}

impl FastbootDevice {
    pub fn init_if_fastboot(
        device: Device<GlobalContext>,
    ) -> Result<Option<Self>, FastbootDeviceInitError> {
        let device_descriptor = device
            .device_descriptor()
            .map_err(FastbootDeviceInitError::GetDeviceDescriptor)?;

        tracing::debug!(
            "Inspecting device: Bus {:03} Device {:03} ID {:04x}:{:04x}",
            device.bus_number(),
            device.address(),
            device_descriptor.vendor_id(),
            device_descriptor.product_id(),
        );

        let config_descriptor = device
            .active_config_descriptor()
            .map_err(FastbootDeviceInitError::GetConfigDescriptor)?;

        let handle = device.open().map_err(FastbootDeviceInitError::Open)?;

        let product = handle
            .read_product_string_ascii(&device_descriptor)
            .map_err(FastbootDeviceInitError::Product)?;

        if product.as_str() != FASTBOOT_PRODUCT {
            return Ok(None);
        }

        let serial = handle
            .read_serial_number_string_ascii(&device_descriptor)
            .map_err(FastbootDeviceInitError::Serial)?;

        let manufacturer = handle
            .read_manufacturer_string_ascii(&device_descriptor)
            .ok();

        // Any error or missing component from here should be treated as an error rather than an unrecognised device as the device reported itself as "Fastboot"

        let max_packet_size = match device.speed() {
            rusb::Speed::Full => FastbootMaxPacketSize::Full,
            rusb::Speed::High => FastbootMaxPacketSize::High,
            rusb::Speed::Super | rusb::Speed::SuperPlus => FastbootMaxPacketSize::Super,
            speed => return Err(FastbootDeviceInitError::InvalidDeviceSpeed(speed)),
        };

        let mut found_interface = false;
        let mut endpoints = (None, None);
        'outer: for interface in config_descriptor.interfaces() {
            for descriptor in interface.descriptors() {
                let interface_class = descriptor.class_code();
                let interface_subclass = descriptor.sub_class_code();
                let interface_endpoint_count = descriptor.num_endpoints();

                if interface_class == FASTBOOT_INTERFACE_CLASS
                    && interface_subclass == FASTBOOT_INTERFACE_SUBCLASS
                {
                    found_interface = true;

                    if interface_endpoint_count != 2 {
                        return Err(FastbootDeviceInitError::InterfaceWrongEndpointCount(
                            interface_endpoint_count,
                        ));
                    }

                    handle.reset().map_err(FastbootDeviceInitError::Reset)?;
                    handle
                        .set_active_configuration(config_descriptor.number())
                        .map_err(FastbootDeviceInitError::SetActiveConfiguration)?;
                    handle
                        .claim_interface(interface.number())
                        .map_err(FastbootDeviceInitError::ClaimInterface)?;
                    handle
                        .set_alternate_setting(interface.number(), descriptor.setting_number())
                        .map_err(FastbootDeviceInitError::AlternateSetting)?;

                    for endpoint in descriptor.endpoint_descriptors() {
                        if endpoint.transfer_type() == TransferType::Bulk {
                            match endpoint.direction() {
                                rusb::Direction::In => {
                                    tracing::trace!(
                                        "Found bulk in endpoint: {}",
                                        endpoint.address()
                                    );
                                    endpoints.0 = Some(endpoint.address());
                                }
                                rusb::Direction::Out => {
                                    tracing::trace!(
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
            return Err(FastbootDeviceInitError::MissingInterface);
        }

        let (in_endpoint, out_endpoint) = match endpoints {
            (None, None) => return Err(FastbootDeviceInitError::InterfaceMissingBulkEndpoints),
            (None, Some(_)) => return Err(FastbootDeviceInitError::InterfaceMissingBulkInEndpoint),
            (Some(_), None) => {
                return Err(FastbootDeviceInitError::InterfaceMissingBulkOutEndpoint);
            }
            (Some(in_endpoint), Some(out_endpoint)) => (in_endpoint, out_endpoint),
        };

        Ok(Some(Self {
            handle,
            serial,
            manufacturer,
            in_endpoint,
            out_endpoint,
            max_packet_size,
        }))
    }

    pub fn serial(&self) -> &str {
        &self.serial
    }

    pub fn manufacturer(&self) -> Option<&str> {
        self.manufacturer.as_deref()
    }

    fn write_raw(&self, data: &[u8]) -> Result<(), FastbootDeviceRuntimeError> {
        tracing::trace!("Writing {data:02x?}");
        assert!(
            self.max_packet_size.bytes() >= data.len(),
            "Attempted raw packet write with a too large packet"
        );

        let amount = self
            .handle
            .write_bulk(self.out_endpoint, data, TIMEOUT_DURATION)
            .map_err(FastbootDeviceRuntimeError::Write)?;

        if amount != data.len() {
            return Err(FastbootDeviceRuntimeError::WriteTooSmall(
                amount,
                data.len(),
            ));
        }

        Ok(())
    }

    fn read_raw<const NO_TIMEOUT: bool>(
        &self,
        buffer: &mut [u8],
    ) -> Result<usize, FastbootDeviceRuntimeError> {
        let amt = self
            .handle
            .read_bulk(
                self.in_endpoint,
                buffer,
                if NO_TIMEOUT {
                    std::time::Duration::MAX
                } else {
                    TIMEOUT_DURATION
                },
            )
            .map_err(FastbootDeviceRuntimeError::Read)?;
        tracing::trace!("Read {:02x?}", &buffer[..amt]);
        Ok(amt)
    }

    fn read_response<const NO_TIMEOUT: bool>(
        &self,
    ) -> Result<FastbootResponse, FastbootDeviceRuntimeError> {
        let mut buffer = [0u8; 64];

        let amt = self.read_raw::<NO_TIMEOUT>(&mut buffer)?;
        tracing::debug!("Read command response: {:02x?}", &buffer[..amt]);

        if amt < 4 {
            return Err(FastbootDeviceRuntimeError::ReadTypeTooSmall);
        }

        match &buffer[0..4] {
            b"INFO" => {
                let extra = match buffer.len() > 4 {
                    false => String::new(),
                    true => String::from_utf8(buffer[4..amt].to_vec())
                        .map_err(|_| FastbootDeviceRuntimeError::ResponseInfoInvalidAscii)?,
                };

                Ok(FastbootResponse::Info(extra))
            }
            b"FAIL" => {
                let extra = match buffer.len() > 4 {
                    false => String::new(),
                    true => String::from_utf8(buffer[4..amt].to_vec())
                        .map_err(|_| FastbootDeviceRuntimeError::ResponseFailInvalidAscii)?,
                };

                Ok(FastbootResponse::Fail(extra))
            }
            b"OKAY" => {
                let extra = match buffer.len() > 4 {
                    false => String::new(),
                    true => String::from_utf8(buffer[4..amt].to_vec())
                        .map_err(|_| FastbootDeviceRuntimeError::ResponseOkInvalidAscii)?,
                };

                Ok(FastbootResponse::Ok(extra))
            }
            b"DATA" => {
                if amt != 12 {
                    return Err(FastbootDeviceRuntimeError::ResponseDataInvalidSize(amt));
                }

                let number_str = str::from_utf8(&buffer[4..12])
                    .map_err(|_| FastbootDeviceRuntimeError::ResponseDataInvalidNumber)?;
                let number = u32::from_str_radix(number_str, 16)
                    .map_err(|_| FastbootDeviceRuntimeError::ResponseDataInvalidNumber)?;

                Ok(FastbootResponse::Data(number))
            }
            data => {
                tracing::debug!("Read invalid response data: {data:02x?}");
                return Err(FastbootDeviceRuntimeError::InvalidResponseType);
            }
        }
    }

    pub fn read_response_full(&self) -> Result<SendCommandResponse, FastbootDeviceRuntimeError> {
        loop {
            match self.read_response::<false>()? {
                FastbootResponse::Info(string) => {
                    tracing::debug!("Device resp INFO: '{string}'");
                    println!("{string}");
                }
                FastbootResponse::Fail(string) => {
                    tracing::debug!("Device resp FAIL: '{string}'");
                    return Ok(SendCommandResponse::Fail(string));
                }
                FastbootResponse::Ok(string) => {
                    tracing::debug!("Device resp OK: '{string}'");
                    return Ok(SendCommandResponse::Ok(string));
                }
                FastbootResponse::Data(amount) => {
                    tracing::debug!("Device resp DATA {amount:08X}");
                    return Ok(SendCommandResponse::Data(amount));
                }
            }
        }
    }

    pub fn read_response_full_no_timeout(
        &self,
    ) -> Result<SendCommandResponse, FastbootDeviceRuntimeError> {
        loop {
            match self.read_response::<true>()? {
                FastbootResponse::Info(string) => {
                    tracing::debug!("Device resp INFO: '{string}'");
                    println!("{string}");
                }
                FastbootResponse::Fail(string) => {
                    tracing::debug!("Device resp FAIL: '{string}'");
                    return Ok(SendCommandResponse::Fail(string));
                }
                FastbootResponse::Ok(string) => {
                    tracing::debug!("Device resp OK: '{string}'");
                    return Ok(SendCommandResponse::Ok(string));
                }
                FastbootResponse::Data(amount) => {
                    tracing::debug!("Device resp DATA {amount:08X}");
                    return Ok(SendCommandResponse::Data(amount));
                }
            }
        }
    }

    pub fn read_data(&self, data: &mut [u8]) -> Result<(), FastbootDeviceRuntimeError> {
        let mut amt = 0;

        while amt < data.len() {
            let iter = (128 * 1024).min(data.len() - amt);
            self.read_raw::<false>(&mut data[amt..amt + iter])?;
            amt += iter;
        }

        Ok(())
    }

    pub fn send_data(&self, data: &[u8]) -> Result<(), FastbootDeviceRuntimeError> {
        let mut amt = 0;

        while amt < data.len() {
            let iter = self.max_packet_size.bytes().min(data.len() - amt);
            self.write_raw(&data[amt..amt + iter])?;
            amt += iter;
        }

        Ok(())
    }

    pub fn send_command(
        &self,
        command: &str,
    ) -> Result<SendCommandResponse, FastbootDeviceRuntimeError> {
        if !command.is_ascii() {
            return Err(FastbootDeviceRuntimeError::CommandNonAscii);
        }

        if command.len() > 64 {
            return Err(FastbootDeviceRuntimeError::CommandTooLong(command.len()));
        }

        tracing::debug!("Sending command: '{command}'");
        self.write_raw(command.as_bytes())?;

        self.read_response_full()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastbootResponse {
    Info(String),
    Fail(String),
    Ok(String),
    Data(u32),
}
