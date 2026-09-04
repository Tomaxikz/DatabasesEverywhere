const LOWER_DIGITS: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn encode_lower(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(char::from(LOWER_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) const fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_ascii_hex() {
        assert_eq!(encode_lower(&[0x00, 0xab, 0xff]), "00abff");
        for (digit, value) in [(b'0', 0), (b'9', 9), (b'a', 10), (b'F', 15)] {
            assert_eq!(nibble(digit), Some(value));
        }
        assert_eq!(nibble(b'g'), None);
    }
}
