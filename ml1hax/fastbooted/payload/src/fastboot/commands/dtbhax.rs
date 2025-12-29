use core::str::FromStr;

use gpt_disk_types::{GptPartitionName, GptPartitionType, LbaLe};

use crate::{
    fastboot::{FastbootCommandHandlerRes, fastboot_fail, fastboot_okay, flash::FlashDevice},
    handle_disk_res, try_something,
};

const DTBHAX_BACKUP_PARTITION: &str = "DTBHAX";
const CPUBL_PARTITION: &str = "cpu-bootloader";
const KDTB_PARTITION: &str = "kernel-dtb";
const USER_PARTITION: &str = "UDA";

const DTBHAX_LOAD_ADDR: usize = 0x92000000;
const CBOOT_LOAD_ADDR: usize = 0x96000000;

const SLIDE_OFFSET: u64 = (CBOOT_LOAD_ADDR - DTBHAX_LOAD_ADDR) as u64;

const NEEDED_LEN: u64 = const {
    let len = ((CBOOT_LOAD_ADDR + 0x7000) - DTBHAX_LOAD_ADDR) as u64;
    assert!((CBOOT_LOAD_ADDR - DTBHAX_LOAD_ADDR) > PAYLOAD.len());
    assert!(len % 4096 == 0);
    assert!(len > SLIDE_OFFSET);
    len
};

const PAYLOAD: &[u8] = include_bytes!("dtbhax.bin");

pub fn fastboot_dtbhax_setup(_args: &[u8]) -> FastbootCommandHandlerRes {
    let Some(mut flash) = FlashDevice::new(false) else {
        _ = fastboot_fail(b"Failed to open flash block device");
        return FastbootCommandHandlerRes::DropDevice;
    };

    let flash_copy = flash;

    let mut disk = handle_disk_res!(gpt_disk_io::Disk::new(&mut flash), b"DTBHAX-Open");
    let mut block_buf = [0u8; 4096 * 2];

    let mut header = handle_disk_res!(
        disk.read_primary_gpt_header(&mut block_buf),
        b"DTBHAX-RPGPTH"
    );
    let mut entry_count = header.number_of_partition_entries.to_u32();
    if entry_count != 39 {
        _ = fastboot_fail(b"Failed to read partition layout");
        return FastbootCommandHandlerRes::DropDevice;
    }
    entry_count += 1;
    header.number_of_partition_entries.set(entry_count);
    let Ok(layout) = header.get_partition_entry_array_layout() else {
        _ = fastboot_fail(b"header.number_of_partition_entries != 39 ???");
        return FastbootCommandHandlerRes::DropDevice;
    };
    let mut array = handle_disk_res!(
        disk.read_gpt_partition_entry_array(layout, &mut block_buf),
        b"DTBHAX-GETITER"
    );
    let Ok(cpubl_entry_name) = GptPartitionName::from_str(CPUBL_PARTITION) else {
        _ = fastboot_fail(b"Invalid partition name (cpu-bootloader)?");
        return FastbootCommandHandlerRes::DropDevice;
    };
    let Ok(dtbhax_entry_name) = GptPartitionName::from_str(DTBHAX_BACKUP_PARTITION) else {
        _ = fastboot_fail(b"Invalid partition name (dtbhax)?");
        return FastbootCommandHandlerRes::DropDevice;
    };
    let Ok(kdtb_entry_name) = GptPartitionName::from_str(KDTB_PARTITION) else {
        _ = fastboot_fail(b"Invalid partition name (kernel-dtb)?");
        return FastbootCommandHandlerRes::DropDevice;
    };
    let Ok(user_entry_name) = GptPartitionName::from_str(USER_PARTITION) else {
        _ = fastboot_fail(b"Invalid partition name (user)?");
        return FastbootCommandHandlerRes::DropDevice;
    };

    let slice = unsafe { core::slice::from_raw_parts_mut(0x8000_0000 as *mut u8, 0x7000) };

    for idx in 0..=entry_count {
        let Some(entry) = array.get_partition_entry_mut(idx) else {
            _ = fastboot_fail(b"Missing partition (cpubl)");
            return FastbootCommandHandlerRes::DropDevice;
        };

        if entry.name == cpubl_entry_name {
            if let Err(_) = flash_copy
                .device
                .read(slice, entry.starting_lba.to_u64() * 4096)
            {
                _ = fastboot_fail(b"Failed to read partition (cpubl)");
                return FastbootCommandHandlerRes::DropDevice;
            }
            break;
        }
    }

    let mut kdtb_partition_found = false;
    for idx in 0..=entry_count {
        let Some(entry) = array.get_partition_entry_mut(idx) else {
            _ = fastboot_fail(b"Missing partition (ktbd out-of-entries)");
            return FastbootCommandHandlerRes::DropDevice;
        };

        if entry.name == kdtb_entry_name {
            kdtb_partition_found = true;
            entry.name = dtbhax_entry_name;
            break;
        }
    }

    if !kdtb_partition_found {
        _ = fastboot_fail(b"Missing partition (kernel-dtb out-of-indexes)");
        return FastbootCommandHandlerRes::DropDevice;
    };

    let mut new_lbas = None;
    for idx in 0..=entry_count {
        let Some(entry) = array.get_partition_entry_mut(idx) else {
            _ = fastboot_fail(b"Missing partition (3)");
            return FastbootCommandHandlerRes::DropDevice;
        };

        if entry.name == user_entry_name {
            let needed_lbas = NEEDED_LEN / 4096;
            let ending_lba = entry.ending_lba.to_u64();
            let starting_lba = ending_lba - needed_lbas;
            entry.ending_lba = LbaLe::from_u64(starting_lba - 1);
            new_lbas = Some((starting_lba, ending_lba));
            break;
        }
    }

    let Some((new_kdtb_start_lba, new_kdtb_end_lba)) = new_lbas else {
        _ = fastboot_fail(b"Missing partition (3)");
        return FastbootCommandHandlerRes::DropDevice;
    };

    for idx in 0..=entry_count {
        let Some(entry) = array.get_partition_entry_mut(idx) else {
            break;
        };

        if entry.is_used() || !entry.name.is_empty() {
            continue;
        }

        entry.name = kdtb_entry_name;
        entry.partition_type_guid = GptPartitionType::BASIC_DATA;
        entry.starting_lba = LbaLe::from_u64(new_kdtb_start_lba);
        entry.ending_lba = LbaLe::from_u64(new_kdtb_end_lba);

        let array_crc32 = array.calculate_crc32();
        handle_disk_res!(
            disk.write_gpt_partition_entry_array(&array),
            b"DTBHAX-WRITE-ARRAY"
        );
        drop(array);

        header.partition_entry_array_crc32 = array_crc32;
        header.update_header_crc32();

        try_something!(
            disk.write_primary_gpt_header(&header, &mut block_buf),
            b"DTBHAX-WRITE-HDR"
        );

        drop(disk);
        try_something!(
            flash.device.write(PAYLOAD, new_kdtb_start_lba * 4096),
            b"DTBHAX-WRITE-PAYLOAD"
        );

        slice[0x6c78..0x6c7c].copy_from_slice(&[0xCB, 0xE4, 0xFF, 0x16]);
        try_something!(
            flash
                .device
                .write(slice, (new_kdtb_start_lba * 4096) + SLIDE_OFFSET),
            b"DTBHAX-WRITE-PATCHED"
        );

        try_something!(fastboot_okay(b"Success!"));
        return FastbootCommandHandlerRes::Continue;
    }

    _ = fastboot_fail(b"Out of indexes");
    FastbootCommandHandlerRes::DropDevice
}
