use core::arch::naked_asm;

#[unsafe(link_section = ".text.start")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    naked_asm!(
        r#"
            mrs     r0, apsr
            bic     r0, r0, #0x1f
            mov     r2, #0x0d48
            lsl     r2, r2, #8
            orr     r2, #0x4f
            lsl     r2, r2, #8
            orr     r2, #0x24
            orr     r1, r0, #0x12
            msr     cpsr_c, r1
            mov     sp, r2
            orr     r1, r0, #0x11
            msr     cpsr_c, r1
            mov     sp, r2
            orr     r1, r0, #0x17
            msr     cpsr_c, r1
            mov     sp, r2
            orr     r1, r0, #0x1b
            msr     cpsr_c, r1
            mov     sp, r2
            orr     r1, r0, #0x1f
            msr     cpsr_c, r1
            mov     sp, r2
            orr     r1, r0, #0x13
            msr     cpsr_c, r1
            mov     sp, r2

            blx  _init
            b .
            "#
    );
}

#[unsafe(link_section = ".text.init")]
pub fn clear_bss() {
    unsafe extern "C" {
        static __bss_start: u8;
        static __bss_end: u8;
    }

    unsafe {
        let start = (&__bss_start) as *const _ as usize;
        let end = (&__bss_end) as *const _ as usize;

        for ptr in start..end {
            *(ptr as *mut u8) = 0;
        }
    }

    unsafe {
        let start = 0xd481df0usize;
        let end = 0xd482f20usize;

        for ptr in start..end {
            *(ptr as *mut u8) = 0;
        }
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.init")]
pub extern "C" fn _init() -> ! {
    clear_bss();

    // Fixup the syscall dispatcher we broke during exploitation
    unsafe {
        core::ptr::write_volatile(0xd481c40 as *mut u32, 0xe59f001c);
        core::ptr::write_volatile(0xd481c44 as *mut u32, 0xe59f101c);
        core::ptr::write_volatile(0xd481c48 as *mut u32, 0xe0411000);
        core::ptr::write_volatile(0xd481c4c as *mut u32, 0xe59f0018);
    }

    crate::main();
    #[allow(clippy::empty_loop)]
    loop {}
}
