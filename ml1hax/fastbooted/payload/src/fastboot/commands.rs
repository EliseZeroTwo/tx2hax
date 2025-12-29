#[cfg(not(feature = "dtbhax"))]
mod dtbhax;
mod dump;
mod fuses;
mod partitions;
mod security;
mod utils;

#[cfg(not(feature = "dtbhax"))]
pub(super) use dtbhax::*;
pub(super) use dump::*;
pub(super) use fuses::*;
pub(super) use partitions::*;
pub(super) use security::*;
pub(super) use utils::*;

#[macro_export]
macro_rules! try_something {
    ($something:expr, $msg:literal) => {
        if $something.is_err() {
            _ = $crate::fastboot::fastboot_fail($msg);
            return $crate::fastboot::FastbootCommandHandlerRes::DropDevice;
        }
    };

    ($something:expr) => {
        if $something.is_err() {
            return FastbootCommandHandlerRes::DropDevice;
        }
    };
}
