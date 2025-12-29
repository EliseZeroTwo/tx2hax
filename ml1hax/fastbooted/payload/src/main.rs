#![no_std]
#![no_main]
#![feature(concat_bytes)]
#![allow(clippy::needless_range_loop)]

use core::arch::asm;

pub mod fastboot;
mod setup;

fn poweroff() {
    unsafe {
        asm!(
            "smc #0",
            in("x0") 0x84000008u64,
            in("x1") 0u64,
            in("x2") 0u64,
            in("x3") 0u64
        )
    };
}

fn reboot() {
    unsafe {
        asm!(
            "smc #0",
            in("x0") 0x84000009u64,
            in("x1") 0u64,
            in("x2") 0u64,
            in("x3") 0u64
        )
    };
}

fn main() -> ! {
    fastboot::run_fastboot_server();
}
