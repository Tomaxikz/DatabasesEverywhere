use crate::{server::backup::BackupStoreError, utils::hex::nibble};

pub(super) fn xml_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut values = Vec::new();
    let mut remainder = xml;
    while let Some(start) = remainder.find(&open) {
        let value = &remainder[start + open.len()..];
        let Some(end) = value.find(&close) else {
            break;
        };
        values.push(value[..end].to_string());
        remainder = &value[end + close.len()..];
    }
    values
}

pub(super) fn xml_value(xml: &str, tag: &str) -> Option<String> {
    xml_values(xml, tag).into_iter().next()
}

pub(super) fn xml_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

pub(super) fn percent_decode(value: &str) -> Result<String, BackupStoreError> {
    let bytes = value.as_bytes();
    let hex_digit_at = |position: usize| bytes.get(position).copied().and_then(nibble);
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let (Some(high), Some(low)) = (hex_digit_at(index + 1), hex_digit_at(index + 2)) else {
            return Err(BackupStoreError::Corrupt(
                "S3 returned an invalid percent-encoded object key".to_string(),
            ));
        };
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| BackupStoreError::Corrupt("S3 returned a non-UTF-8 object key".to_string()))
}
