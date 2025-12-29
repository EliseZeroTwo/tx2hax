/// These externs are for the CBoot in the latest firmware version released by Magic-Leap before EOL (to my knowledge)
use core::num::NonZeroU32;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UsbfInfo {
    pub reopen: u32,
    pub usb_class: u32,
}

pub const FASTBOOT_USB_CLASS: u32 = 1;
pub static FASTBOOT_INFO: UsbfInfo = UsbfInfo {
    reopen: 0,
    usb_class: FASTBOOT_USB_CLASS,
};

pub fn transport_usbf_open(usb_info: &UsbfInfo) -> Result<(), NonZeroU32> {
    type TransportUsbfOpen = extern "C" fn(u32, *const UsbfInfo) -> u32;
    const TRANSPORT_USBF_OPEN_ADDR: u64 = 0x96059608u64;
    let transport_usbf_open_inner: TransportUsbfOpen =
        unsafe { core::mem::transmute(TRANSPORT_USBF_OPEN_ADDR as *const ()) };
    let res = transport_usbf_open_inner(0, usb_info as *const _);
    NonZeroU32::new(res).map(Err).unwrap_or(Ok(()))
}

pub fn transport_usbf_receive(buffer: &mut [u8]) -> Result<u32, NonZeroU32> {
    type TransportUsbfReceive = extern "C" fn(*const u8, u32, *mut u32, u64) -> u32;
    const TRANSPORT_USBF_RECEIVE_ADDR: u64 = 0x96059474u64;
    let transport_usbf_receive_inner: TransportUsbfReceive =
        unsafe { core::mem::transmute(TRANSPORT_USBF_RECEIVE_ADDR as *const ()) };
    let mut bytes_read = 0u32;
    let res = transport_usbf_receive_inner(
        buffer.as_mut_ptr(),
        buffer.len() as u32,
        &raw mut bytes_read,
        u64::MAX,
    );
    NonZeroU32::new(res).map(Err).unwrap_or(Ok(bytes_read))
}

pub fn transport_usbf_send(buffer: &[u8]) -> Result<u32, NonZeroU32> {
    type TransportUsbfSend = extern "C" fn(*const u8, u32, *mut u32, u64) -> u32;
    const TRANSPORT_USBF_SEND_ADDR: u64 = 0x9605930cu64;
    let transport_usbf_send_inner: TransportUsbfSend =
        unsafe { core::mem::transmute(TRANSPORT_USBF_SEND_ADDR as *const ()) };
    let mut bytes_sent = 0u32;
    let res = transport_usbf_send_inner(
        buffer.as_ptr(),
        buffer.len() as u32,
        &raw mut bytes_sent,
        u64::MAX,
    );
    NonZeroU32::new(res).map(Err).unwrap_or(Ok(bytes_sent))
}

pub fn se_aes_encrypt_decrypt_raw(
    keyslot: u8,
    keysize: u8,
    first: bool,
    num_blocks: u32,
    src: *const u8,
    dst: *mut u8,
    is_encrypt: bool,
) -> Result<(), NonZeroU32> {
    type SeAesEncryptDecrypt = extern "C" fn(u8, u8, bool, u32, *const u8, *mut u8, bool) -> u32;
    const SE_AES_ENC_DEC_ADDR: u64 = 0x9605660cu64;
    let se_aes_enc_dec_inner: SeAesEncryptDecrypt =
        unsafe { core::mem::transmute(SE_AES_ENC_DEC_ADDR as *const ()) };
    let res = se_aes_enc_dec_inner(keyslot, keysize, first, num_blocks, src, dst, is_encrypt);
    NonZeroU32::new(res).map(Err).unwrap_or(Ok(()))
}

pub fn se_aes_encrypt_decrypt(
    keyslot: u8,
    keysize: u8,
    first: bool,
    num_blocks: u32,
    src: &[u8],
    dst: &mut [u8],
    is_encrypt: bool,
) -> Result<(), NonZeroU32> {
    se_aes_encrypt_decrypt_raw(
        keyslot,
        keysize,
        first,
        num_blocks,
        src.as_ptr(),
        dst.as_mut_ptr(),
        is_encrypt,
    )
}

/// * NAND is 128GiB
///
/// * QSPI flash is 16MiB
#[repr(u32)]
pub enum BlockDeviceType {
    SdmmcBoot = 0,
    SdmmcUser = 1,
    SdmmcRpmb = 2,
    QspiFlash = 3,
    Sata = 4,
    UsbMs = 5,
    SdCard = 6,
    Ufs = 7,
    UfsUser = 8,
    UfsRpmb = 9,
    Nvme = 10,
}

#[derive(Clone, Copy)]
pub struct BlockDevice(*mut core::ffi::c_void);

impl BlockDevice {
    pub fn open(block_device_type: BlockDeviceType) -> Option<Self> {
        // 9603a430    void* tegrabl_blockdev_open(uint32_t storage_type, uint32_t instance)
        type BlockDevOpen = extern "C" fn(u32, u32) -> *mut core::ffi::c_void;
        const BLOCKDEV_OPEN: u64 = 0x9603a430;
        let block_dev_open: BlockDevOpen =
            unsafe { core::mem::transmute(BLOCKDEV_OPEN as *const ()) };

        let res = block_dev_open(block_device_type as u32, 0);
        if res.is_null() {
            return None;
        }

        Some(BlockDevice(res))
    }

    pub fn read(&self, buffer: &mut [u8], offset: u64) -> Result<(), NonZeroU32> {
        // 9603a648    tegrabl_error_t tegrabl_blockdev_read(void* dev, void* buf, uint64_t offset, uint64_t len)
        type BlockDevRead = extern "C" fn(*mut core::ffi::c_void, *mut u8, u64, u64) -> u32;
        const BLOCKDEV_READ: u64 = 0x9603a648;
        let block_dev_read: BlockDevRead =
            unsafe { core::mem::transmute(BLOCKDEV_READ as *const ()) };
        let res = block_dev_read(self.0, buffer.as_mut_ptr(), offset, buffer.len() as u64);
        NonZeroU32::new(res).map(Err).unwrap_or(Ok(()))
    }

    pub fn write(&self, buffer: &[u8], offset: u64) -> Result<(), NonZeroU32> {
        // _ = fastboot_info(b"-- Stubbed write --");
        // _ = fastboot_info(b"Offset: ");
        // _ = fastboot_info(&payload_helpers::u64_to_bytes(offset));
        // _ = fastboot_info(b"Len: ");
        // _ = fastboot_info(&payload_helpers::u64_to_bytes(buffer.len() as u64));
        // _ = fastboot_info(b"-- Stubbed write End --");

        // Ok(())
        // 9603aaf8    uint64_t tegrabl_blockdev_write(void* dev, void const* buf, uint64_t offset, uint64_t len)
        type BlockDevWrite = extern "C" fn(*mut core::ffi::c_void, *const u8, u64, u64) -> u32;
        const BLOCKDEV_WRITE: u64 = 0x9603aaf8;
        let block_dev_write: BlockDevWrite =
            unsafe { core::mem::transmute(BLOCKDEV_WRITE as *const ()) };
        let res = block_dev_write(self.0, buffer.as_ptr(), offset, buffer.len() as u64);
        NonZeroU32::new(res).map(Err).unwrap_or(Ok(()))
    }
}

pub fn fuse_size(fuse_type: u8) -> Result<u32, NonZeroU32> {
    // 96035338    tegrabl_error_t tegrabl_fuse_query_size(uint64_t type, uint32_t* size_out)
    let mut size = 0u32;
    type FuseSize = extern "C" fn(u64, *mut u32) -> u32;
    const FUSE_SIZE: u64 = 0x96035338;
    let tegrabl_fuse_query_size: FuseSize = unsafe { core::mem::transmute(FUSE_SIZE as *const ()) };

    let res = tegrabl_fuse_query_size(fuse_type as u64, &raw mut size);
    NonZeroU32::new(res).map(Err).unwrap_or(Ok(size))
}

// // 9603b12c tegrabl_error_t tegrabl_blockdev_ioctl(tegrabl_bdev_t *dev, uint32_t ioctl, void *args)
// type BlockDevIoctl = extern "C" fn(BlockDev, u32, *mut core::ffi::c_void);
// const BLOCKDEV_IOCTL: u64 = 0x9603b12c;
// let block_dev_ioctl: BlockDevIoctl = unsafe { core::mem::transmute(BLOCKDEV_IOCTL as *const ()) };

pub fn fuse_read(fuse_type: u8, out: &mut [u8]) -> Result<(), NonZeroU32> {
    // 96035424    tegrabl_error_t tegrabl_fuse_read(uint8_t fuse_type, uint32_t* buffer, uint32_t size)
    type FuseRead = extern "C" fn(u8, *mut u8, u32) -> u32;
    const FUSE_READ: u64 = 0x96035424;
    let tegrabl_fuse_read: FuseRead = unsafe { core::mem::transmute(FUSE_READ as *const ()) };

    let res = tegrabl_fuse_read(fuse_type, out.as_mut_ptr(), out.len() as u32);
    NonZeroU32::new(res).map(Err).unwrap_or(Ok(()))
}

pub fn fuse_get_security_info() -> u64 {
    // 960352ec    uint64_t tegrabl_fuse_get_security_info()
    type FuseGetSecurityInfo = extern "C" fn() -> u64;
    const FUSE_GET_SECURITY_INFO: u64 = 0x960352ec;
    let tegrabl_fuse_get_security_info: FuseGetSecurityInfo =
        unsafe { core::mem::transmute(FUSE_GET_SECURITY_INFO as *const ()) };

    tegrabl_fuse_get_security_info()
}

pub fn map_address_uncached(address: usize, length: usize) {
    // `96005db0    void arch_map_uncached(void* vaddr, uint64_t size)`
    type MapUncached = extern "C" fn(*mut core::ffi::c_void, u64);
    const MAP_UNCACHED: u64 = 0x96005db0;
    let arch_map_uncached: MapUncached = unsafe { core::mem::transmute(MAP_UNCACHED as *const ()) };
    arch_map_uncached(address as *mut core::ffi::c_void, length as u64);
}

pub fn arm64_mmu_map(address: u64, length: u64, flags: u32) {
    // 96005840    void arm64_mmu_map(void* paddr, void* vaddr, uint64_t size, uint32_t flags)
    type Arm64MmuMap = extern "C" fn(*mut core::ffi::c_void, *mut core::ffi::c_void, u64, u32);
    const ARM64_MMU_MAP: u64 = 0x96005840;
    let arm64_mmu_map_inner: Arm64MmuMap =
        unsafe { core::mem::transmute(ARM64_MMU_MAP as *const ()) };

    arm64_mmu_map_inner(address as *mut _, address as *mut _, length, flags);
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TegrablModule {
    ClkRst = 0x0,
    Uart = 0x1,
    Sdmmc = 0x2,
    Qspi = 0x3,
    SecurityEngine = 0x4,
    XUsbHost = 0x5,
    XUsbDevice = 0x6,
    XUsbPadControl = 0x7,
    XUsbSuperSpeed = 0x8,
    XUsbF = 0x9,
    DPAux1 = 0xA,
    Host1X = 0xB,
    Cldvfs = 0xC,
    I2c = 0xD,
    SorSafe = 0xE,
    Mem = 0xF,
    KFuse = 0x10,
    NVDec = 0x11,
    GpcDma = 0x12,
    BpmpDma = 0x13,
    SpeDma = 0x14,
    SocTherm = 0x15,
    Ape = 0x16,
    Adsp = 0x17,
    Apb2Ape = 0x18,
    Sata = 0x19,
    Pwm = 0x1A,
    Dsi = 0x1B,
    Sor = 0x1C,
    SorOut = 0x1D,
    SorPadClkOut = 0x1E,
    DPAux = 0x1F,
    NVDisplayHub = 0x20,
    NVDisplayDsc = 0x21,
    NVDisplayDisp = 0x22,
    NVDisplayP = 0x23,
    NVDisplay0Head = 0x24,
    NVDisplay0WGrp = 0x25,
    NVDisplay0Misc = 0x26,
    Spi = 0x27,
    AudMClk = 0x28,
    CpuInit = 0x29,
    SataOob = 0x2A,
    SataCold = 0x2B,
    Mphy = 0x2C,
    Ufs = 0x2D,
    UfsDevRef = 0x2E,
    UfsHcCgSys = 0x2F,
    UPHY = 0x30,
    PexUsbUPhy = 0x31,
    PexUsbUPhyPllMgmnt = 0x32,
    PciE = 0x33,
    PciEXClk = 0x34,
    Afi = 0x35,
    DpAux2 = 0x36,
    DpAux3 = 0x37,
    PexSataUsbRxByp = 0x38,
    Vic = 0x39,
    AxiCbb = 0x3A,
    Eqos = 0x3B,
    PcieApb = 0x3C,
    PcieCore = 0x3D,
}

pub fn clock_enable(module: TegrablModule, instance: u8) -> Result<(), NonZeroU32> {
    // 9604883c    tegrabl_error_t tegrabl_car_clk_enable(uint32_t module, char instance, void* priv_data)
    type ClockEnable = extern "C" fn(u32, u8, *const core::ffi::c_void) -> u32;
    const CLOCK_ENABLE: u64 = 0x9604883c;
    let clock_enable: ClockEnable = unsafe { core::mem::transmute(CLOCK_ENABLE as *const ()) };
    let res = clock_enable(module as u32, instance, core::ptr::null());
    NonZeroU32::new(res).map(Err).unwrap_or(Ok(()))
}
