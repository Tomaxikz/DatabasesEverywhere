use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("Rfc3339 formatting works")
}
