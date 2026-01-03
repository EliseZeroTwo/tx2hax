use aes::cipher::{BlockDecryptMut as _, KeyIvInit as _};
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};

const EMPTY_BLOCK: &[u8; 0x10] = &[0u8; 0x10];
fn decrypt(key: &[u8; 0x10], buffer: &mut [u8; 0x10]) {
    cbc::Decryptor::<aes::Aes128>::new(key.into(), EMPTY_BLOCK.into())
        .decrypt_block_b2b_mut(EMPTY_BLOCK.into(), buffer.into());
}

pub fn sehax(
    vector_0123: &[u8; 0x10],
    vector_012: &[u8; 0x10],
    vector_01: &[u8; 0x10],
    vector_0: &[u8; 0x10],
) -> Option<[u8; 0x10]> {
    let mut base_key = [0u8; 0x10];

    let expected = [vector_0, vector_01, vector_012, vector_0123];

    for idx in 0..4 {
        if let Some(item) = (0..=u32::MAX).into_par_iter().find_any(|attempt| {
            let mut buffer = [0u8; 16];
            let mut key = base_key;
            key[(idx * 4)..((idx + 1) * 4)].copy_from_slice(&attempt.to_le_bytes());
            decrypt(&key, &mut buffer);

            &buffer == expected[idx]
        }) {
            base_key[(idx * 4)..((idx + 1) * 4)].copy_from_slice(&item.to_le_bytes());
        } else {
            println!("Not found on idx {idx} :c");
            return None;
        }
    }

    Some(base_key)
}
