use crate::{
    fastboot::{
        FastbootCommandHandlerRes, externs::transport_usbf_send, fastboot_data, fastboot_fail,
        fastboot_info, fastboot_okay,
    },
    try_something,
};

pub fn fastboot_fuse_read_id(arg: &[u8]) -> FastbootCommandHandlerRes {
    const BASE_COMMAND_LEN: usize = b"read-fuse-id:".len();
    if arg.len() < BASE_COMMAND_LEN + 1 {
        _ = fastboot_fail(b"Invalid Arguments!");
        return FastbootCommandHandlerRes::DropDevice;
    }
    let Ok(id) = u8::from_str_radix(
        match core::str::from_utf8(&arg[BASE_COMMAND_LEN..BASE_COMMAND_LEN + 2]) {
            Ok(s) => s,
            Err(_) => {
                _ = fastboot_fail(b"Invalid characters in ID!");
                return FastbootCommandHandlerRes::DropDevice;
            }
        },
        16,
    ) else {
        _ = fastboot_fail(b"Invalid ID!");
        return FastbootCommandHandlerRes::DropDevice;
    };

    try_something!(fastboot_info(b"Reading Fuse: "));
    try_something!(fastboot_info(&payload_helpers::u32_to_data_len(id as u32)));

    let Ok(size) = crate::fastboot::externs::fuse_size(id) else {
        _ = fastboot_fail(b"Failed to read fuse size!");
        return FastbootCommandHandlerRes::DropDevice;
    };

    try_something!(fastboot_info(b"Fuse Size: "));
    try_something!(fastboot_info(&payload_helpers::u32_to_data_len(
        size as u32
    )));

    if size > 0x100 {
        _ = fastboot_fail(b"Fuse too large!");
        return FastbootCommandHandlerRes::DropDevice;
    }

    let mut buffer = [0u8; 0x100];
    if let Err(_) = crate::fastboot::externs::fuse_read(id, &mut buffer[..size as usize]) {
        _ = fastboot_fail(b"Failed to read fuse!");
        return FastbootCommandHandlerRes::DropDevice;
    }
    // let buffer = crate::fastboot::externs::fuse_get_security_info().to_le_bytes();

    try_something!(fastboot_data(size));
    try_something!(transport_usbf_send(&buffer[..size as usize]));

    try_something!(fastboot_okay(b""));

    FastbootCommandHandlerRes::Continue
}

pub fn fastboot_fuse_read_raw(arg: &[u8]) -> FastbootCommandHandlerRes {
    const BASE_COMMAND_LEN: usize = b"read-fuse-raw:".len();
    if arg.len() < BASE_COMMAND_LEN + 4 {
        _ = fastboot_fail(b"Invalid Arguments!");
        return FastbootCommandHandlerRes::DropDevice;
    }
    let Ok(offset) = u32::from_str_radix(
        match core::str::from_utf8(&arg[BASE_COMMAND_LEN..BASE_COMMAND_LEN + 4]) {
            Ok(s) => s,
            Err(_) => {
                _ = fastboot_fail(b"Invalid characters in offset!");
                return FastbootCommandHandlerRes::DropDevice;
            }
        },
        16,
    ) else {
        _ = fastboot_fail(b"Invalid offset!");
        return FastbootCommandHandlerRes::DropDevice;
    };
    let buffer = tx2_common::mmio::mmio_read(0, 0x3820000 | offset as usize).to_le_bytes();
    // let buffer = crate::fastboot::externs::fuse_get_security_info().to_le_bytes();

    try_something!(fastboot_data(buffer.len() as u32));
    try_something!(transport_usbf_send(&buffer));

    try_something!(fastboot_okay(b""));

    FastbootCommandHandlerRes::Continue
}
