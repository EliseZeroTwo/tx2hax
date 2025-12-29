use externs::{transport_usbf_receive, transport_usbf_send};

pub mod commands;
pub mod externs;
pub mod flash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastbootResError {
    MessageTooLong,
    Ext(core::num::NonZeroU32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastbootCommandHandlerRes {
    Continue,
    DropDevice,
}

pub struct FastbootCommand {
    pub prefix: &'static [u8],
    pub handler: &'static dyn Fn(&[u8]) -> FastbootCommandHandlerRes,
}

impl FastbootCommand {
    pub const fn new(
        prefix: &'static [u8],
        handler: &'static impl Fn(&[u8]) -> FastbootCommandHandlerRes,
    ) -> Self {
        Self {
            prefix,
            handler: handler as &dyn Fn(&[u8]) -> FastbootCommandHandlerRes,
        }
    }
}

macro_rules! fastboot_ack {
    ($ty:literal, $msg:expr) => {{
        if $msg.len() > 60 {
            return Err(FastbootResError::MessageTooLong);
        }

        let mut buffer = [0u8; 0x40];
        buffer[0] = $ty[0];
        buffer[1] = $ty[1];
        buffer[2] = $ty[2];
        buffer[3] = $ty[3];
        buffer[4..$msg.len() + 4].copy_from_slice($msg);

        transport_usbf_send(&buffer[..$msg.len() + 4]).map_err(FastbootResError::Ext)?;

        Ok(())
    }};
}

pub fn fastboot_ack(ack_type: &[u8], message: &[u8]) -> Result<(), FastbootResError> {
    if message.len() > 60 {
        return Err(FastbootResError::MessageTooLong);
    }

    let mut buffer = [0u8; 0x40];
    buffer[0] = ack_type[0];
    buffer[1] = ack_type[1];
    buffer[2] = ack_type[2];
    buffer[3] = ack_type[3];
    buffer[4..message.len() + 4].copy_from_slice(message);

    transport_usbf_send(&buffer[..message.len() + 4]).map_err(FastbootResError::Ext)?;

    Ok(())
}

pub fn fastboot_info(message: &[u8]) -> Result<(), FastbootResError> {
    fastboot_ack!(b"INFO", message)
}

pub fn fastboot_fail(message: &[u8]) -> Result<(), FastbootResError> {
    fastboot_ack!(b"FAIL", message)
}

pub fn fastboot_okay(message: &[u8]) -> Result<(), FastbootResError> {
    fastboot_ack!(b"OKAY", message)
}

pub fn fastboot_data(len: u32) -> Result<(), FastbootResError> {
    let len = payload_helpers::u32_to_data_len(len);
    fastboot_ack!(b"DATA", &len)
}

pub fn run_fastboot_server() -> ! {
    let mut buffer = [0u8; 64];
    'outer: loop {
        while externs::transport_usbf_open(&externs::FASTBOOT_INFO).is_err() {}

        'inner: loop {
            buffer.fill(0);
            let res = transport_usbf_receive(&mut buffer);

            let Ok(bytes_read) = res.map(|x| x as usize) else {
                break 'inner;
            };

            let res = match &buffer[..bytes_read] {
                cmd if cmd.starts_with(b"owo") => commands::fastboot_owo(cmd),
                cmd if cmd.starts_with(b"reboot") => commands::fastboot_reboot(cmd),
                cmd if cmd.starts_with(b"poweroff") => commands::fastboot_poweroff(cmd),
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"dump-mem:") => commands::fastboot_dump_mem(cmd),
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"dump-qspi") => commands::fastboot_dump_qspi(cmd),
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"dump-flash") => commands::fastboot_dump_flash(cmd),
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"read-fuse-id:") => commands::fastboot_fuse_read_id(cmd),
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"read-fuse-raw:") => commands::fastboot_fuse_read_raw(cmd),
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"se-hax-vectors") => {
                    commands::fastboot_se_hax_dump_vectors(cmd)
                }
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"read-sysram") => commands::fastboot_read_sysram(cmd),
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"partitions") => commands::fastboot_list_partitions(cmd),
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"dtbhax:setup") => commands::fastboot_dtbhax_setup(cmd),
                #[cfg(not(feature = "dtbhax"))]
                cmd if cmd.starts_with(b"dump-partition:") => {
                    commands::fastboot_dump_partition(cmd)
                }
                _ => match fastboot_fail(b"Unknown Command...") {
                    Ok(_) => FastbootCommandHandlerRes::Continue,
                    Err(_) => FastbootCommandHandlerRes::DropDevice,
                },
            };

            match res {
                FastbootCommandHandlerRes::Continue => continue 'inner,
                FastbootCommandHandlerRes::DropDevice => continue 'outer,
            }
        }
    }
}
