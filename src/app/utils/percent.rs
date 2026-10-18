//! RFC 3986 percent-encoding on top of the `percent-encoding` crate.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, percent_encode};

/// Every byte except the RFC 3986 unreserved characters `A-Z a-z 0-9 - _ . ~`.
const RESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');
const RESERVED_EXCEPT_SLASH: &AsciiSet = &RESERVED.remove(b'/');

/// Encodes everything but unreserved characters, with uppercase hex digits.
pub(crate) fn encode_unreserved(bytes: &[u8]) -> String {
    percent_encode(bytes, RESERVED).to_string()
}

/// Like [`encode_unreserved`], but keeps `/` path separators.
pub(crate) fn encode_path(bytes: &[u8]) -> String {
    percent_encode(bytes, RESERVED_EXCEPT_SLASH).to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// A `%` not followed by two hex digits.
    Encoding,
    /// The decoded bytes are not UTF-8.
    Utf8,
}

/// Decodes `%XX` escapes and refuses malformed escapes instead of passing
/// them through as the lenient crate decoder does. `+` stays a plus.
pub(crate) fn decode_strict(value: &str) -> Result<String, DecodeError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while let Some(offset) = bytes[index..].iter().position(|byte| *byte == b'%') {
        let escape = index + offset;
        let digits = bytes
            .get(escape + 1..escape + 3)
            .ok_or(DecodeError::Encoding)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(DecodeError::Encoding);
        }
        index = escape + 3;
    }
    percent_decode_str(value)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|_| DecodeError::Utf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_only_reserved_bytes_with_uppercase_hex() {
        assert_eq!(encode_unreserved(b"a b/c+$~-_."), "a%20b%2Fc%2B%24~-_.");
        assert_eq!(encode_path(b"a b/c"), "a%20b/c");
        assert_eq!(encode_unreserved("é".as_bytes()), "%C3%A9");
    }

    #[test]
    fn strict_decoding_refuses_malformed_escapes_and_non_utf8() {
        assert_eq!(decode_strict("a%20b+c%2f").unwrap(), "a b+c/");
        for malformed in ["%", "%4", "%zz", "a%2"] {
            assert_eq!(
                decode_strict(malformed),
                Err(DecodeError::Encoding),
                "{malformed}"
            );
        }
        assert_eq!(decode_strict("%ff"), Err(DecodeError::Utf8));
    }
}
