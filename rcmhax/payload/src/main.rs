#![no_std]
#![no_main]

use crate::mmio::{mmio_or, mmio_read, mmio_write, tmrus};

mod externs;
pub mod mmio;
mod setup;

fn usleep(usecs: u32) {
    let end = tmrus().wrapping_add(usecs);

    while tmrus() < end {}
}

fn reset() -> ! {
    loop {
        mmio_or(0xc360000, 1 << 4);
    }
}

fn usb_logln(s: &[u8]) {
    unsafe {
        let offset: usize = core::ptr::read_volatile(0x4000_0000 as *const u32) as usize;
        core::ptr::copy_nonoverlapping(
            s.as_ptr(),
            (0x4000_0004usize as *mut u8).add(offset),
            s.len(),
        );

        core::ptr::write_volatile((0x4000_0004 + offset + s.len()) as *mut u8, b'\r');
        core::ptr::write_volatile((0x4000_0004 + offset + s.len() + 1) as *mut u8, b'\n');
        core::ptr::write_volatile(0x4000_0000 as *mut u32, (offset + s.len() + 2) as u32);
    }
}
fn usb_flush() {
    unsafe {
        let length: u32 = core::ptr::read_volatile(0x4000_0000 as *const u32);
        let mut bytes_read = 0u32;
        externs::NvBootXusbDeviceTransmit(
            0x4000_0004usize as *const _,
            length,
            &raw mut bytes_read,
        );

        core::ptr::write_volatile(0x4000_0000 as *mut u32, 0u32);
    }
}

fn write_hex_nibble(value: u8, out: &mut u8) {
    let value = value & 0x0F;
    let amt = if value < 0xA { b'0' } else { b'A' - 0xA };
    *out = value + amt;
}

fn write_hex_u8(value: u8, out: &mut [u8]) {
    write_hex_nibble(value >> 4, &mut out[0]);
    write_hex_nibble(value, &mut out[1]);
}

fn clean_ch(ch: u8, out: &mut u8) {
    #[allow(clippy::manual_range_contains)]
    if ch >= 0x20 && ch < 0x7F {
        *out = ch;
    } else {
        *out = b'.'
    }
}

fn main() {
    mmio_write(0xD000108, 0x30000);

    externs::NvBootRcmSetupPortHandle(1);
    externs::NvBootXusbDeviceInit();
    externs::NvBootXusbDeviceEnumerate();
    externs::NvBootRcmSendUniqueId();

    usleep(1000 * 1000 * 2);
    usb_logln(b"Hi NVidia! Miau from the TX2 BootROM!\r\n");

    let sbk_u32s: [u32; 4] = core::array::from_fn(|idx| mmio_read(0x38201a4 + (idx as u32 * 4)));
    let sbk: [u8; 16] = core::array::from_fn(|idx| (sbk_u32s[idx / 4] >> (8 * (idx % 4))) as u8);
    let mut buffer = *b"0000000000000000000000000000000000000000000000000000000000000000";

    #[cfg(feature = "log-sbk")]
    {
        usb_logln(b"Here's this devices SBK:");
        for x in 0..16 {
            write_hex_u8(sbk[x], &mut buffer[x * 2..(x * 2) + 2]);
        }
        usb_logln(&buffer[..32]);
    }

    usb_flush();

    usb_logln(b"SHA256(Secure Boot Key):");
    {
        let hash_buffer = unsafe { core::slice::from_raw_parts_mut(0x40002040 as *mut u8, 32) };
        let sbk_sysram_slice =
            unsafe { core::slice::from_raw_parts_mut(0x40002020 as *mut u8, 16) };
        sbk_sysram_slice.copy_from_slice(&sbk);
        externs::ShaHash(sbk_sysram_slice.as_ptr(), 16, hash_buffer.as_mut_ptr(), 5);
        for x in 0..32 {
            write_hex_u8(hash_buffer[x], &mut buffer[x * 2..(x * 2) + 2]);
        }
    }
    usb_logln(&buffer);

    usb_flush();

    usb_logln(b"\r\nHere's 0x200 bytes of the protected BootROM:");

    const MEOW: &[u8] =
        b"00000000 - 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 - ................";

    let mut addr = 0x2ca00;
    let mut buffer = [0u8; 0x100];
    for _ in 0..32 {
        buffer[..MEOW.len()].copy_from_slice(MEOW);
        write_hex_u8((addr >> 24) as u8, &mut buffer[0..]);
        write_hex_u8((addr >> 16) as u8, &mut buffer[2..]);
        write_hex_u8((addr >> 8) as u8, &mut buffer[4..]);
        write_hex_u8(addr as u8, &mut buffer[6..]);

        for idx in 0usize..4 {
            let mut val = mmio_read(addr);
            for subidx in 0..4 {
                write_hex_u8(val as u8, &mut buffer[11 + (((idx * 4) + subidx) * 3)..]);
                clean_ch(val as u8, &mut buffer[61 + (idx * 4) + subidx]);
                val >>= 8;
            }
            addr += 4;
        }
        usb_logln(&buffer[..MEOW.len()]);
    }

    usb_flush();
    usleep(1000 * 1000 * 5);
    reset()
}
