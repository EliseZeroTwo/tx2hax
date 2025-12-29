use crate::{
    fastboot::{
        FastbootCommandHandlerRes, externs::transport_usbf_send, fastboot_data, fastboot_okay,
    },
    try_something,
};

fn aes_set_keyslot_partial(keyslot: u32, idx: u32, val: u32) {
    tx2_common::mmio::mmio_write(
        tx2_common::mmio::security_engine::SE_BASE,
        tx2_common::mmio::security_engine::CRYPTO_KEYTABLE_ADDR,
        (keyslot << 4) | idx as u32,
    );
    tx2_common::mmio::mmio_write(
        tx2_common::mmio::security_engine::SE_BASE,
        tx2_common::mmio::security_engine::CRYPTO_KEYTABLE_DATA,
        val,
    );
}

fn aes_set_iv_partial(keyslot: u32, updated: bool, idx: u32, val: u32) {
    let updated = match updated {
        true => 1u32,
        false => 0u32,
    };

    tx2_common::mmio::mmio_write(
        tx2_common::mmio::security_engine::SE_BASE,
        tx2_common::mmio::security_engine::CRYPTO_KEYTABLE_ADDR,
        (keyslot << 4) | (1 << 3) | (updated << 2) | idx as u32,
    );
    tx2_common::mmio::mmio_write(
        tx2_common::mmio::security_engine::SE_BASE,
        tx2_common::mmio::security_engine::CRYPTO_KEYTABLE_DATA,
        val,
    );
}

fn fastboot_se_hax_dump_vectors_inner(keyslot: u8) -> FastbootCommandHandlerRes {
    aes_set_iv_partial(keyslot as u32, false, 0, 0);
    aes_set_iv_partial(keyslot as u32, false, 1, 0);
    aes_set_iv_partial(keyslot as u32, false, 2, 0);
    aes_set_iv_partial(keyslot as u32, false, 3, 0);
    aes_set_iv_partial(keyslot as u32, false, 4, 0);
    aes_set_iv_partial(keyslot as u32, false, 5, 0);
    aes_set_iv_partial(keyslot as u32, false, 6, 0);
    aes_set_iv_partial(keyslot as u32, false, 7, 0);
    aes_set_iv_partial(keyslot as u32, true, 0, 0);
    aes_set_iv_partial(keyslot as u32, true, 1, 0);
    aes_set_iv_partial(keyslot as u32, true, 2, 0);
    aes_set_iv_partial(keyslot as u32, true, 3, 0);
    aes_set_iv_partial(keyslot as u32, true, 4, 0);
    aes_set_iv_partial(keyslot as u32, true, 5, 0);
    aes_set_iv_partial(keyslot as u32, true, 6, 0);
    aes_set_iv_partial(keyslot as u32, true, 7, 0);

    let start_1 = [0u8; 0x10];
    let mut expected_0123 = [0u8; 0x10];
    let mut expected_012 = [0u8; 0x10];
    let mut expected_01 = [0u8; 0x10];
    let mut expected_0 = [0u8; 0x10];
    let mut expected_empty = [0u8; 0x10];

    try_something!(
        crate::fastboot::externs::se_aes_encrypt_decrypt(
            keyslot,
            0,
            true,
            1,
            &start_1,
            &mut expected_0123,
            true
        ),
        b"Encrypt1 failed"
    );
    aes_set_keyslot_partial(keyslot as u32, 3, 0u32);
    try_something!(
        crate::fastboot::externs::se_aes_encrypt_decrypt(
            keyslot,
            0,
            true,
            1,
            &start_1,
            &mut expected_012,
            true
        ),
        b"Encrypt1 failed"
    );
    aes_set_keyslot_partial(keyslot as u32, 2, 0u32);
    try_something!(
        crate::fastboot::externs::se_aes_encrypt_decrypt(
            keyslot,
            0,
            true,
            1,
            &start_1,
            &mut expected_01,
            true
        ),
        b"Encrypt1 failed"
    );
    aes_set_keyslot_partial(keyslot as u32, 1, 0u32);
    try_something!(
        crate::fastboot::externs::se_aes_encrypt_decrypt(
            keyslot,
            0,
            true,
            1,
            &start_1,
            &mut expected_0,
            true
        ),
        b"Encrypt1 failed"
    );
    aes_set_keyslot_partial(keyslot as u32, 0, 0u32);
    try_something!(
        crate::fastboot::externs::se_aes_encrypt_decrypt(
            keyslot,
            0,
            true,
            1,
            &start_1,
            &mut expected_empty,
            true
        ),
        b"Encrypt1 failed"
    );

    let mut buffer = [0u8; 0x60];
    buffer[..0x10].copy_from_slice(&start_1);
    buffer[0x10..0x20].copy_from_slice(&expected_empty);
    buffer[0x20..0x30].copy_from_slice(&expected_0);
    buffer[0x30..0x40].copy_from_slice(&expected_01);
    buffer[0x40..0x50].copy_from_slice(&expected_012);
    buffer[0x50..0x60].copy_from_slice(&expected_0123);

    try_something!(fastboot_data(0x60));
    try_something!(transport_usbf_send(&buffer));

    FastbootCommandHandlerRes::Continue
}

pub fn fastboot_se_hax_dump_vectors(_arg: &[u8]) -> FastbootCommandHandlerRes {
    for keyslot in 0..16 {
        if fastboot_se_hax_dump_vectors_inner(keyslot) == FastbootCommandHandlerRes::DropDevice {
            return FastbootCommandHandlerRes::DropDevice;
        }
    }

    try_something!(fastboot_okay(b""));
    FastbootCommandHandlerRes::Continue
}

pub fn fastboot_read_sysram(_arg: &[u8]) -> FastbootCommandHandlerRes {
    let src = [0u8; 0x10];
    let mut dst = [0u8; 0x10];
    let keyslot = 1u32;
    aes_set_iv_partial(keyslot as u32, false, 0, 0);
    aes_set_iv_partial(keyslot as u32, false, 1, 0);
    aes_set_iv_partial(keyslot as u32, false, 2, 0);
    aes_set_iv_partial(keyslot as u32, false, 3, 0);
    aes_set_iv_partial(keyslot as u32, false, 4, 0);
    aes_set_iv_partial(keyslot as u32, false, 5, 0);
    aes_set_iv_partial(keyslot as u32, false, 6, 0);
    aes_set_iv_partial(keyslot as u32, false, 7, 0);
    aes_set_iv_partial(keyslot as u32, true, 0, 0);
    aes_set_iv_partial(keyslot as u32, true, 1, 0);
    aes_set_iv_partial(keyslot as u32, true, 2, 0);
    aes_set_iv_partial(keyslot as u32, true, 3, 0);
    aes_set_iv_partial(keyslot as u32, true, 4, 0);
    aes_set_iv_partial(keyslot as u32, true, 5, 0);
    aes_set_iv_partial(keyslot as u32, true, 6, 0);
    aes_set_iv_partial(keyslot as u32, true, 7, 0);
    aes_set_keyslot_partial(keyslot, 0, 0u32);
    aes_set_keyslot_partial(keyslot, 1, 0u32);
    aes_set_keyslot_partial(keyslot, 2, 0u32);
    aes_set_keyslot_partial(keyslot, 3, 0u32);
    try_something!(
        crate::fastboot::externs::se_aes_encrypt_decrypt_raw(
            keyslot as u8,
            0,
            true,
            1,
            src.as_ptr(),
            // 0x30000000 as *mut u8,
            dst.as_mut_ptr(),
            true
        ),
        b"Encrypt failed"
    );

    try_something!(fastboot_data(0x10));
    try_something!(transport_usbf_send(&dst));
    try_something!(fastboot_okay(b""));

    FastbootCommandHandlerRes::Continue
}
