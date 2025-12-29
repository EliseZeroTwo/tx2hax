use crate::{
    fastboot::{
        FastbootCommandHandlerRes, externs::transport_usbf_send, fastboot_data, fastboot_fail,
        fastboot_info, fastboot_okay, flash::FlashDevice,
    },
    handle_disk_res, try_something,
};

pub(crate) fn fastboot_list_partitions(arg: &[u8]) -> FastbootCommandHandlerRes {
    const BASE_COMMAND_LEN: usize = b"partitions:".len();
    const QSPI_LEN: usize = b"qspi".len();
    const UFS_LEN: usize = b"ufs".len();

    if arg.len() < BASE_COMMAND_LEN + UFS_LEN {
        _ = fastboot_fail(b"Invalid Arguments!");
        return FastbootCommandHandlerRes::DropDevice;
    }

    try_something!(fastboot_info(b"Parsing argument..."));

    let is_qspi = if &arg[BASE_COMMAND_LEN..BASE_COMMAND_LEN + UFS_LEN] == b"ufs" {
        false
    } else if &arg[BASE_COMMAND_LEN..BASE_COMMAND_LEN + QSPI_LEN] == b"qspi" {
        true
    } else {
        _ = fastboot_fail(b"Invalid Partition Source!");
        return FastbootCommandHandlerRes::DropDevice;
    };

    try_something!(match is_qspi {
        true => fastboot_info(b"Parsed argument, is_qspi=true..."),
        false => fastboot_info(b"Parsed argument, is_qspi=false..."),
    });

    let Some(mut flash) = FlashDevice::new(is_qspi) else {
        _ = fastboot_fail(b"Failed to open flash block device");
        return FastbootCommandHandlerRes::DropDevice;
    };

    try_something!(fastboot_info(b"Opened disk"));

    let mut disk = handle_disk_res!(gpt_disk_io::Disk::new(&mut flash), b"LP-Open");
    let mut block_buf = [0u8; 4096 * 2];

    try_something!(fastboot_info(b"Parsed disk"));

    // let primary_header =
    // handle_disk_res!(disk.read_primary_gpt_header(&mut block_buf), b"LP-RPGPTH");
    let header = match is_qspi {
        true => handle_disk_res!(disk.read_secondary_gpt_header(&mut block_buf), b"DP-RPGPTH"),
        false => handle_disk_res!(disk.read_primary_gpt_header(&mut block_buf), b"DP-RPGPTH"),
    };
    try_something!(fastboot_info(b"Read phdr"));

    let Ok(layout) = header.get_partition_entry_array_layout() else {
        _ = fastboot_fail(b"Failed to read partition layout");
        return FastbootCommandHandlerRes::DropDevice;
    };
    try_something!(fastboot_info(b"Got layout"));

    let iter = handle_disk_res!(
        disk.gpt_partition_entry_array_iter(layout, &mut block_buf),
        b"LP-GETITER"
    );

    try_something!(fastboot_info(b"Got Iter"));

    let block_size = match is_qspi {
        true => 512,
        false => 4096,
    };

    for item in iter {
        try_something!(fastboot_info(b"Item"));
        let item = handle_disk_res!(item, b"LP-ITERITEM");
        _ = fastboot_info(b"--- Partition ---");
        let mut name = [0u8; 72];
        let mut name_end = 0;
        for (idx, ch) in item.name.chars().enumerate() {
            name[idx] = ch as u8;
            name_end = idx;
        }
        _ = fastboot_info(b"Name:");
        _ = fastboot_info(&name[..name_end + 1]);
        _ = fastboot_info(b"Start:");
        let start_bytes = payload_helpers::u64_to_bytes(item.starting_lba.to_u64() * block_size);
        _ = fastboot_info(&start_bytes);
        _ = fastboot_info(b"End:");
        let end_bytes = payload_helpers::u64_to_bytes(item.ending_lba.to_u64() * block_size);
        _ = fastboot_info(&end_bytes);
    }

    _ = fastboot_okay(b"");

    FastbootCommandHandlerRes::Continue
}

pub(crate) fn fastboot_dump_partition(arg: &[u8]) -> FastbootCommandHandlerRes {
    const BASE_COMMAND_LEN: usize = b"dump-partition:".len();
    const QSPI_LEN: usize = b"qspi:".len();
    const UFS_LEN: usize = b"ufs:".len();

    if arg.len() < BASE_COMMAND_LEN + UFS_LEN + 1 {
        _ = fastboot_fail(b"Invalid Arguments!");
        return FastbootCommandHandlerRes::DropDevice;
    }

    let is_qspi = if &arg[BASE_COMMAND_LEN..BASE_COMMAND_LEN + UFS_LEN] == b"ufs:" {
        false
    } else if &arg[BASE_COMMAND_LEN..BASE_COMMAND_LEN + QSPI_LEN] == b"qspi:" {
        true
    } else {
        _ = fastboot_fail(b"Invalid Partition Source!");
        return FastbootCommandHandlerRes::DropDevice;
    };

    let Some(mut flash) = FlashDevice::new(is_qspi) else {
        _ = fastboot_fail(b"Failed to open flash block device");
        return FastbootCommandHandlerRes::DropDevice;
    };

    let partition_name_start = match is_qspi {
        true => BASE_COMMAND_LEN + QSPI_LEN,
        false => BASE_COMMAND_LEN + UFS_LEN,
    };

    let partition_name = &arg[partition_name_start..];

    let mut disk = handle_disk_res!(gpt_disk_io::Disk::new(&mut flash), b"DP-Open");
    let mut block_buf = [0u8; 4096 * 2];

    let header = match is_qspi {
        true => handle_disk_res!(disk.read_secondary_gpt_header(&mut block_buf), b"DP-RPGPTH"),
        false => handle_disk_res!(disk.read_primary_gpt_header(&mut block_buf), b"DP-RPGPTH"),
    };
    let Ok(layout) = header.get_partition_entry_array_layout() else {
        _ = fastboot_fail(b"Failed to read partition layout");
        return FastbootCommandHandlerRes::DropDevice;
    };
    let iter = handle_disk_res!(
        disk.gpt_partition_entry_array_iter(layout, &mut block_buf),
        b"DP-GETITER"
    );

    let block_size = match is_qspi {
        true => 512,
        false => 4096,
    };
    for item in iter {
        let item = handle_disk_res!(item, b"DP-ITERITEM");
        let mut name = [0u8; 72];
        let mut name_end = 0;
        for (idx, ch) in item.name.chars().enumerate() {
            name[idx] = ch as u8;
            name_end = idx;
        }
        if &name[..name_end + 1] == partition_name {
            let Some(flash) = FlashDevice::new(is_qspi) else {
                _ = fastboot_fail(b"Failed to open flash block device (2)");
                return FastbootCommandHandlerRes::DropDevice;
            };
            let start = item.starting_lba.to_u64() * block_size;
            let end = (item.ending_lba.to_u64() + 1) * block_size;
            let bytes = end - start;

            let mut offset = start;
            let mut remaining = bytes;
            let mut ufs_buffer = [0u8; 32 * 1024];
            let mut qspi_buffer = [0u8; 4 * 1024];
            let buffer = match is_qspi {
                true => &mut qspi_buffer[..],
                false => &mut ufs_buffer[..],
            };
            while remaining != 0 {
                let iter_amount = remaining.min(u32::MAX as u64);
                try_something!(fastboot_data(iter_amount as u32));

                let mut iter_remaining = iter_amount as usize;
                while iter_remaining != 0 {
                    let iter_len = iter_remaining.min(buffer.len());

                    try_something!(
                        flash.device.read(&mut buffer[..iter_len], offset),
                        b"Block device read failed"
                    );
                    try_something!(transport_usbf_send(&buffer[..iter_len]));

                    offset += iter_len as u64;
                    iter_remaining -= iter_len;
                }

                remaining -= iter_amount;
            }

            try_something!(fastboot_okay(b"Success!"));

            return FastbootCommandHandlerRes::Continue;
        }
    }

    _ = fastboot_fail(b"Partition not found on disk!");
    FastbootCommandHandlerRes::DropDevice
}
