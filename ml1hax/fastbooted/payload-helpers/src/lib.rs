#![no_std]

pub const fn nibble_to_bytechar(nibble: u8) -> u8 {
    match nibble & 0b1111 {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        9 => b'9',
        10 => b'A',
        11 => b'B',
        12 => b'C',
        13 => b'D',
        14 => b'E',
        15 => b'F',
        _ => b'?',
    }
}

pub const fn u32_to_data_len(len: u32) -> [u8; 8] {
    let be_bytes = len.to_be_bytes();
    [
        nibble_to_bytechar(be_bytes[0] >> 4),
        nibble_to_bytechar(be_bytes[0]),
        nibble_to_bytechar(be_bytes[1] >> 4),
        nibble_to_bytechar(be_bytes[1]),
        nibble_to_bytechar(be_bytes[2] >> 4),
        nibble_to_bytechar(be_bytes[2]),
        nibble_to_bytechar(be_bytes[3] >> 4),
        nibble_to_bytechar(be_bytes[3]),
    ]
}

pub const fn u64_to_bytes(len: u64) -> [u8; 16] {
    let be_bytes = len.to_be_bytes();
    [
        nibble_to_bytechar(be_bytes[0] >> 4),
        nibble_to_bytechar(be_bytes[0]),
        nibble_to_bytechar(be_bytes[1] >> 4),
        nibble_to_bytechar(be_bytes[1]),
        nibble_to_bytechar(be_bytes[2] >> 4),
        nibble_to_bytechar(be_bytes[2]),
        nibble_to_bytechar(be_bytes[3] >> 4),
        nibble_to_bytechar(be_bytes[3]),
        nibble_to_bytechar(be_bytes[4] >> 4),
        nibble_to_bytechar(be_bytes[4]),
        nibble_to_bytechar(be_bytes[5] >> 4),
        nibble_to_bytechar(be_bytes[5]),
        nibble_to_bytechar(be_bytes[6] >> 4),
        nibble_to_bytechar(be_bytes[6]),
        nibble_to_bytechar(be_bytes[7] >> 4),
        nibble_to_bytechar(be_bytes[7]),
    ]
}

#[cfg(test)]
mod tests {
    macro_rules! u32_to_data_len_test {
        ($value:literal, $expected:literal) => {
            paste::paste! {
                #[allow(non_snake_case)]
                #[test]
                fn [<u32_to_data_len_ $value>]() {
                    assert_eq!(
                        $expected,
                        &super::u32_to_data_len($value),
                    );
                }
            }
        };
    }

    macro_rules! u64_to_bytes_test {
        ($value:literal, $expected:literal) => {
            paste::paste! {
                #[allow(non_snake_case)]
                #[test]
                fn [<u64_to_bytes_ $value>]() {
                    assert_eq!(
                        $expected,
                        &super::u64_to_bytes($value),
                    );
                }
            }
        };
    }

    u32_to_data_len_test!(0, b"00000000");
    u32_to_data_len_test!(1, b"00000001");
    u32_to_data_len_test!(0x0100, b"00000100");
    u32_to_data_len_test!(0xA1B2C3D4, b"A1B2C3D4");
    u32_to_data_len_test!(0x1A2B3C4D, b"1A2B3C4D");
    u32_to_data_len_test!(0xAA01B020, b"AA01B020");
    u32_to_data_len_test!(0x000100B0, b"000100B0");

    u64_to_bytes_test!(0, b"0000000000000000");
    u64_to_bytes_test!(1, b"0000000000000001");
    u64_to_bytes_test!(0x0100, b"0000000000000100");
    u64_to_bytes_test!(0xA1B2C3D4, b"00000000A1B2C3D4");
    u64_to_bytes_test!(0x1A2B3C4D, b"000000001A2B3C4D");
    u64_to_bytes_test!(0xAA01B020, b"00000000AA01B020");
    u64_to_bytes_test!(0x000100B0, b"00000000000100B0");
    u64_to_bytes_test!(0xA1B2C3D4A1B2C3D4, b"A1B2C3D4A1B2C3D4");
    u64_to_bytes_test!(0x1A2B3C4D1A2B3C4D, b"1A2B3C4D1A2B3C4D");
    u64_to_bytes_test!(0xAA01B020AA01B020, b"AA01B020AA01B020");
    u64_to_bytes_test!(0x000100B0000100B0, b"000100B0000100B0");
}
