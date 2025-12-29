macro_rules! extern_fn {
    ($addr:literal as fn $name:ident($($aname:ident: $aty:ty),*) $(-> $rty:ty)?) => {
        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        pub extern "C" fn $name($($aname: $aty),*) $(-> $rty)? {
            core::arch::naked_asm!(
                r#"
                push {{ r7, lr }}
                mov r7, {}
                lsl r7, #8
                orr r7, {}
                orr r7, #1
                blx r7
                pop {{ r7, pc }}
                "#,
                const ($addr >> 8),
                const ($addr & 0xFF)
            );
        }
    };
}

extern_fn!(0x11a7c as fn NvBootUartInit(osc_freq: u32, is_uart_boot_prod: bool) -> u32);
extern_fn!(0x10b26 as fn NvBootClocksGetOscFreq() -> u32);

extern_fn!(0x19450 as fn NvBootRcmSetupPortHandle(port: u32) -> u32);
extern_fn!(0x1aa64 as fn NvBootXusbDeviceInit() -> u32);
extern_fn!(0x1a7ac as fn NvBootXusbDeviceEnumerate() -> u32);
extern_fn!(0x193a4 as fn NvBootRcmSendUniqueId() -> u32);
extern_fn!(0x1ab58 as fn NvBootXusbDeviceTransmit(buffer: *const u8, bytes: u32, bytes_read: *mut u32) -> u32);
extern_fn!(0x145a0 as fn ShaHash(data: *const u8, data_length: u32, out: *mut u8, hash_type: u32) -> u32);
