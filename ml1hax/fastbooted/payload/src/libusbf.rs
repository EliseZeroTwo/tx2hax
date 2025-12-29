#[repr(C)]
pub struct UsbfPrivInfo {
    pub reopen: bool,
    pub usb_class: u32
}

#[repr(u32)]
pub enum UsbfUsbClass {
    ThreeP = 0,
    Fastboot = 1,
    Charging = 2,
}

type TegraResult = u32;


#[link(name = "usbf")]
unsafe extern "C" {
    /// tegrabl_error_t tegrabl_transport_usbf_open(uint32_t instance, bool reopen, uint32_t usb_class);
    fn tegrabl_transport_usbf_open(
        reopen: bool,
        usb_class: UsbfUsbClass
    ) -> TegraResult;

    /// `tegrabl_error_t tegrabl_transport_usbf_send(const void *buffer, uint32_t length, uint32_t *bytes_transmitted, time_t timeout);`
    fn tegrabl_transport_usbf_send(
        buffer: *const u8,
        length: u32,
        bytes_transmitted: *mut u32,
        timeout_us: u64,
    ) -> TegraResult;

    /// `tegrabl_error_t tegrabl_transport_usbf_receive(void *buf, uint32_t length, uint32_t *received, time_t timeout);`
    fn tegrabl_transport_usbf_receive(
        buffer: *mut u8,
        length: u32,
        bytes_read: *mut u32,
        timeout_us: u64,
    ) -> TegraResult;

    /// `tegrabl_error_t tegrabl_usbf_close(uint32_t instance);`
    fn tegrabl_usbf_close(
        instance: u32
    ) -> TegraResult;
}

pub fn usbf_open(
    reopen: bool,
    usb_class: UsbfUsbClass
) -> TegraResult {
    unsafe {
        tegrabl_transport_usbf_open(reopen, usb_class)
    }
}

pub fn usbf_send(
    buffer: &[u8],
    bytes_transmitted: &mut u32,
    timeout_us: u64,
) -> TegraResult {
    unsafe {
        tegrabl_transport_usbf_send(buffer.as_ptr(), buffer.len() as u32, bytes_transmitted, timeout_us)
    }
}

pub fn usbf_receive(
    buffer: &mut [u8],
    bytes_read: &mut u32,
    timeout_us: u64,
) -> TegraResult {
    unsafe {
        tegrabl_transport_usbf_receive(buffer.as_mut_ptr(), buffer.len() as u32, bytes_read, timeout_us)
    }
}

pub fn usbf_close(
    instance: u32,
) -> TegraResult {
    unsafe {
        tegrabl_usbf_close(instance)
    }
}