use tx2_common::utils::usleep;

use crate::{
    fastboot::{FastbootCommandHandlerRes, fastboot_okay},
    try_something,
};

pub(crate) fn fastboot_owo(_arg: &[u8]) -> FastbootCommandHandlerRes {
    match fastboot_okay(b"Meow from the Bootloader! Good security as ever NVidia!") {
        Ok(_) => FastbootCommandHandlerRes::Continue,
        Err(_) => FastbootCommandHandlerRes::DropDevice,
    }
}

pub(crate) fn fastboot_reboot(_arg: &[u8]) -> FastbootCommandHandlerRes {
    try_something!(fastboot_okay(b"Rebooting!"));
    usleep(25000);
    crate::reboot();
    loop {}
}

pub(crate) fn fastboot_poweroff(_arg: &[u8]) -> FastbootCommandHandlerRes {
    try_something!(fastboot_okay(b"Powering off!"));
    usleep(25000);
    crate::poweroff();
    loop {}
}
