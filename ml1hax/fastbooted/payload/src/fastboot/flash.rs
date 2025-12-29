use core::num::NonZeroU32;

use super::externs::BlockDeviceType;

#[derive(Clone, Copy)]
pub struct FlashDevice {
    pub device: crate::fastboot::externs::BlockDevice,
    is_qspi: bool,
}

impl FlashDevice {
    pub fn new(is_qspi: bool) -> Option<Self> {
        crate::fastboot::externs::BlockDevice::open(match is_qspi {
            true => BlockDeviceType::QspiFlash,
            false => BlockDeviceType::Ufs,
        })
        .map(|device| Self { device, is_qspi })
    }
}

impl gpt_disk_io::BlockIo for &mut FlashDevice {
    type Error = NonZeroU32;

    fn block_size(&self) -> gpt_disk_io::gpt_disk_types::BlockSize {
        match self.is_qspi {
            true => gpt_disk_io::gpt_disk_types::BlockSize::BS_512,
            false => gpt_disk_io::gpt_disk_types::BlockSize::BS_4096,
        }
    }

    fn num_blocks(&mut self) -> Result<u64, Self::Error> {
        Ok(match self.is_qspi {
            true => (1024 * 1024 * 16) / 512,
            false => (1024 * 1024 * 1024 * 128) / 4096,
        })
    }

    fn read_blocks(
        &mut self,
        start_lba: gpt_disk_io::gpt_disk_types::Lba,
        dst: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.device
            .read(dst, start_lba.to_u64() * self.block_size().to_u64())
    }

    fn write_blocks(
        &mut self,
        start_lba: gpt_disk_io::gpt_disk_types::Lba,
        src: &[u8],
    ) -> Result<(), Self::Error> {
        self.device
            .write(src, start_lba.to_u64() * self.block_size().to_u64())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[macro_export]
macro_rules! handle_disk_res {
    ($ex:expr, $section:literal) => {
        match $ex {
            Ok(x) => x,
            Err(gpt_disk_io::DiskError::BlockSizeSmallerThanPartitionEntry) => {
                _ = fastboot_fail(concat_bytes!(
                    b"DiskIO: ",
                    $section,
                    b" BlockSizeSmallerThanPartitionEntry"
                ));
                return FastbootCommandHandlerRes::DropDevice;
            }
            Err(gpt_disk_io::DiskError::BufferTooSmall) => {
                _ = fastboot_fail(concat_bytes!(b"DiskIO: ", $section, b" BufferTooSmall"));
                return FastbootCommandHandlerRes::DropDevice;
            }
            Err(gpt_disk_io::DiskError::Overflow) => {
                _ = fastboot_fail(concat_bytes!(b"DiskIO: ", $section, b" Overflow"));
                return FastbootCommandHandlerRes::DropDevice;
            }
            Err(gpt_disk_io::DiskError::Io(_)) => {
                _ = fastboot_fail(concat_bytes!(b"DiskIO: ", $section, b" IO Error"));
                return FastbootCommandHandlerRes::DropDevice;
            }
        }
    };
}
