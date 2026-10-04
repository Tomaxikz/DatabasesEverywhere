use super::*;
use super::{
    download::append_bounded_chunk,
    listing::decode_listed_key,
    signing::{aws_uri_encode, hmac_sha256},
    upload::multipart_part_size,
    xml::{percent_decode, xml_values},
};
use crate::utils::hex::encode_lower;

#[test]
fn aws_encoding_preserves_only_unreserved_bytes_and_key_slashes() {
    assert_eq!(aws_uri_encode(b"a b/c+$", true), "a%20b/c%2B%24");
    assert_eq!(aws_uri_encode(b"a/b", false), "a%2Fb");
}

#[test]
fn hmac_matches_the_rfc_4231_sha256_vector() {
    let key = [0x0b_u8; 20];
    assert_eq!(
        encode_lower(&hmac_sha256(&key, b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn parses_encoded_s3_keys_without_treating_plus_as_space() {
    let xml = "<ListBucketResult><Contents><Key>dbev/a%20b%2Bc</Key></Contents></ListBucketResult>";
    let key = percent_decode(&xml_values(xml, "Key")[0]).unwrap();
    assert_eq!(key, "dbev/a b+c");
}

#[test]
fn listed_s3_keys_must_remain_inside_the_requested_instance_prefix() {
    assert_eq!(
        decode_listed_key("dbev/instances/a/backup", "dbev/instances/a/").unwrap(),
        "dbev/instances/a/backup"
    );
    let error = decode_listed_key("dbev/instances/b/backup", "dbev/instances/a/").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("outside the requested backup prefix")
    );
}

#[test]
fn multipart_size_stays_within_the_s3_part_limit() {
    assert_eq!(multipart_part_size(64 * 1024 * 1024), 16 * 1024 * 1024);
    let eight_tib = 8 * 1024_u64.pow(4);
    assert!(eight_tib.div_ceil(multipart_part_size(eight_tib)) <= MAX_MULTIPART_PARTS);
}

#[test]
fn bounded_response_chunks_reject_overflow_before_buffering_it() {
    let mut bytes = vec![1_u8, 2];

    let error = append_bounded_chunk(&mut bytes, &[3, 4], 3, "test").unwrap_err();

    assert!(error.to_string().contains("exceeded its safety limit"));
    assert_eq!(bytes, [1, 2]);
}
