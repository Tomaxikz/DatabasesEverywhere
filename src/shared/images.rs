pub fn is_pinned_image_reference(image: &str) -> bool {
    has_sha256_digest(image) || has_non_latest_tag(image)
}

pub fn has_sha256_digest(image: &str) -> bool {
    let Some((name, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    !name.is_empty()
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn has_non_latest_tag(image: &str) -> bool {
    let image_without_digest = image.split_once('@').map(|(name, _)| name).unwrap_or(image);
    let last_slash = image_without_digest.rfind('/');
    let last_colon = image_without_digest.rfind(':');
    let Some(colon) = last_colon else {
        return false;
    };
    if last_slash.is_some_and(|slash| colon < slash) {
        return false;
    }
    let tag = &image_without_digest[colon + 1..];
    !tag.is_empty() && !tag.eq_ignore_ascii_case("latest")
}
