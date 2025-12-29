use crate::{
    fastboot::{
        FastbootCommandHandlerRes,
        externs::{BlockDeviceType, transport_usbf_send},
        fastboot_data, fastboot_fail, fastboot_okay,
    },
    try_something,
};

pub(crate) fn fastboot_dump_qspi(_arg: &[u8]) -> FastbootCommandHandlerRes {
    let Some(block_device) =
        crate::fastboot::externs::BlockDevice::open(BlockDeviceType::QspiFlash)
    else {
        _ = fastboot_fail(b"Failed to open QSPI flash block device");
        return FastbootCommandHandlerRes::DropDevice;
    };

    /// QSPI Flash is 16MiB
    const QSPI_FLASH_LENGTH: usize = 16 * 1024 * 1024;

    try_something!(fastboot_data(QSPI_FLASH_LENGTH as u32));

    let mut buffer = [0u8; 4 * 1024];

    for iter in 0..4096 {
        try_something!(
            block_device.read(&mut buffer, iter * 4096),
            b"Block device read failed"
        );
        try_something!(transport_usbf_send(&buffer));
    }

    try_something!(fastboot_okay(b"Success!"));

    FastbootCommandHandlerRes::Continue
}

pub(crate) fn fastboot_dump_flash(arg: &[u8]) -> FastbootCommandHandlerRes {
    const BASE_COMMAND_LEN: usize = b"dump-flash".len();
    const U64_ARG_LEN: usize = 16;
    if arg.len() < BASE_COMMAND_LEN + U64_ARG_LEN + 2 + U64_ARG_LEN {
        _ = fastboot_fail(b"Invalid Arguments!");
        return FastbootCommandHandlerRes::DropDevice;
    }

    let Ok(sector_start) = u64::from_str_radix(
        match core::str::from_utf8(&arg[BASE_COMMAND_LEN + 1..BASE_COMMAND_LEN + 1 + U64_ARG_LEN]) {
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

    let Ok(sector_count) = u64::from_str_radix(
        match core::str::from_utf8(
            &arg[BASE_COMMAND_LEN + 2 + U64_ARG_LEN..BASE_COMMAND_LEN + 2 + (U64_ARG_LEN * 2)],
        ) {
            Ok(s) => s,
            Err(_) => {
                _ = fastboot_fail(b"Invalid characters in count!");
                return FastbootCommandHandlerRes::DropDevice;
            }
        },
        16,
    ) else {
        _ = fastboot_fail(b"Invalid count!");
        return FastbootCommandHandlerRes::DropDevice;
    };

    let Some(block_device) = crate::fastboot::externs::BlockDevice::open(BlockDeviceType::Ufs)
    else {
        _ = fastboot_fail(b"Failed to open flash block device");
        return FastbootCommandHandlerRes::DropDevice;
    };

    let bytes = sector_count * 4096;

    if bytes > u32::MAX as u64 {
        _ = fastboot_fail(b"Too many sectors");
        return FastbootCommandHandlerRes::DropDevice;
    }

    try_something!(fastboot_data(bytes as u32));

    let mut buffer = [0u8; 16 * 4096];
    let mut offset = sector_start * 4096;
    let mut remaining = bytes as usize;
    while remaining != 0 {
        let iter_len = remaining.min(buffer.len());

        try_something!(
            block_device.read(&mut buffer[..iter_len], offset),
            b"Block device read failed"
        );
        try_something!(transport_usbf_send(&buffer));

        offset += iter_len as u64;
        remaining -= iter_len;
    }

    try_something!(fastboot_okay(b"Success!"));

    FastbootCommandHandlerRes::Continue
}

pub(crate) fn fastboot_dump_mem(arg: &[u8]) -> FastbootCommandHandlerRes {
    const BASE_COMMAND_LEN: usize = b"dump-mem".len();
    const U32_ARG_LEN: usize = 8;
    if arg.len() < BASE_COMMAND_LEN + (U32_ARG_LEN * 2) + 2 {
        _ = fastboot_fail(b"Invalid Arguments!");
        return FastbootCommandHandlerRes::DropDevice;
    }

    let Ok(address) = u32::from_str_radix(
        match core::str::from_utf8(&arg[BASE_COMMAND_LEN + 1..BASE_COMMAND_LEN + 1 + U32_ARG_LEN]) {
            Ok(s) => s,
            Err(_) => {
                _ = fastboot_fail(b"Invalid characters in address!");
                return FastbootCommandHandlerRes::DropDevice;
            }
        },
        16,
    ) else {
        _ = fastboot_fail(b"Invalid address!");
        return FastbootCommandHandlerRes::DropDevice;
    };

    let Ok(length) = u32::from_str_radix(
        match core::str::from_utf8(
            &arg[BASE_COMMAND_LEN + 2 + U32_ARG_LEN..BASE_COMMAND_LEN + 2 + (U32_ARG_LEN * 2)],
        ) {
            Ok(s) => s,
            Err(_) => {
                _ = fastboot_fail(b"Invalid characters in length!");
                return FastbootCommandHandlerRes::DropDevice;
            }
        },
        16,
    ) else {
        _ = fastboot_fail(b"Invalid length!");
        return FastbootCommandHandlerRes::DropDevice;
    };

    try_something!(fastboot_data(length));

    let mut ptr = address as usize;
    let mut remaining = length as usize;

    let mut buffer = [0u8; 512];
    while remaining != 0 {
        let iter_amount = remaining.min(512);

        unsafe {
            core::ptr::copy(ptr as *const u8, buffer.as_mut_ptr(), iter_amount);
        }

        try_something!(transport_usbf_send(&buffer[..iter_amount]));

        ptr += iter_amount;
        remaining -= iter_amount;
    }

    try_something!(fastboot_okay(b"Success!"));

    FastbootCommandHandlerRes::Continue
}
