#![no_std]
#![no_main]

use crate::mmio::{mmio_or, mmio_write, tmrus};

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

pub const SE_BASE: u32 = 0x3ac0000;
pub const CRYPTO_KEYTABLE_ADDR: u32 = 0x2bc;
pub const CRYPTO_KEYTABLE_DATA: u32 = 0x2c0;

fn aes_set_keyslot_partial(keyslot: u32, idx: u32, val: u32) {
    mmio_write(SE_BASE + CRYPTO_KEYTABLE_ADDR, (keyslot << 4) | idx as u32);
    mmio_write(SE_BASE + CRYPTO_KEYTABLE_DATA, val);
}

fn main() {
    mmio_write(0xD000108, 0x30000);

    externs::NvBootRcmSetupPortHandle(1);
    externs::NvBootXusbDeviceInit();
    externs::NvBootXusbDeviceEnumerate();
    externs::NvBootRcmSendUniqueId();

    let mut keys: [u8; 0x40] = [0u8; 0x40];

    for x in 0..4 {
        unsafe {
            core::ptr::write_bytes(0x40008c00 as *mut u8, 0u8, 0x10);
        };

        if x != 0 {
            aes_set_keyslot_partial(3, 4 - x, 0);
        }

        unsafe {
            let f: extern "C" fn(u32, u32, u32, u32, *const u8, *mut u8) -> u32 =
                core::mem::transmute(0x14db9 as *const u8);
            f(3, 0, 1, 1, 0x30008c00 as *const u8, 0x30008c00 as *mut u8);
        }
        let dst: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(0x40008c00 as *mut u8, 16) };
        keys[(x as usize * 0x10)..((x as usize + 1) * 0x10)].copy_from_slice(dst);
    }

    unsafe {
        core::ptr::copy_nonoverlapping(keys.as_ptr(), 0x4000_0000usize as *mut u8, keys.len());
        let mut bytes_read = 0u32;
        externs::NvBootXusbDeviceTransmit(
            0x4000_0000usize as *const _,
            keys.len() as _,
            &raw mut bytes_read,
        );
    }

    usleep(1000 * 1000 * 5);
    reset()
}
