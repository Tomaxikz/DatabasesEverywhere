use super::{environment_value, unique_environment_value};

#[test]
fn reads_an_exact_environment_key_and_preserves_equals_in_the_value() {
    let environment = vec![
        "PASSWORD_EXTRA=wrong".to_string(),
        "PASSWORD=correct=with=equals".to_string(),
    ];

    assert_eq!(
        environment_value(&environment, "PASSWORD").as_deref(),
        Some("correct=with=equals")
    );
    assert_eq!(environment_value(&environment, "MISSING"), None);
}

#[test]
fn protected_environment_lookup_rejects_missing_and_duplicate_values_without_leaking_them() {
    let missing = unique_environment_value(&[], "POSTGRES_PASSWORD", "inst_pg")
        .unwrap_err()
        .to_string();
    assert!(missing.contains("POSTGRES_PASSWORD"));
    assert!(!missing.contains("secret"));

    let duplicate = unique_environment_value(
        &[
            "POSTGRES_PASSWORD=first-secret".to_string(),
            "POSTGRES_PASSWORD=second-secret".to_string(),
        ],
        "POSTGRES_PASSWORD",
        "inst_pg",
    )
    .unwrap_err()
    .to_string();
    assert!(duplicate.contains("duplicate POSTGRES_PASSWORD"));
    assert!(!duplicate.contains("first-secret"));
    assert!(!duplicate.contains("second-secret"));

    assert_eq!(
        unique_environment_value(
            &["POSTGRES_PASSWORD=value=with=equals".to_string()],
            "POSTGRES_PASSWORD",
            "inst_pg",
        )
        .unwrap(),
        "value=with=equals"
    );
}
