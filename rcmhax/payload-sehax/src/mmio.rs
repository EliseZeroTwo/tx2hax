pub const PMC_BASE: u32 = 0xc360000;
pub const APBDEV_PMC_DPD_SAMPLE: u32 = 0x20;
pub const APBDEV_PMC_DPD_ENABLE: u32 = 0x24;

pub const TMR_BASE: u32 = 0xc2e0000;

#[inline(always)]
pub fn mmio_read(addr: u32) -> u32 {
    unsafe { core::ptr::read_volatile(addr as *mut u32) }
}

#[inline(always)]
pub fn mmio_write(addr: u32, value: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
}

#[inline(always)]
pub fn mmio_or(addr: u32, value: u32) {
    mmio_write(addr, mmio_read(addr) | value)
}

#[inline(always)]
pub fn tmrus() -> u32 {
    unsafe { core::ptr::read_volatile(TMR_BASE as *mut u32) }
}
