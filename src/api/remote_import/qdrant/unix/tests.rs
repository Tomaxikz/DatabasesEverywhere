use super::*;

#[test]
fn path_segments_are_encoded() {
    assert_eq!(encode_path_segment("name/a b"), "name%2Fa%20b");
}

#[test]
fn qdrant_snapshot_versions_follow_the_supported_upgrade_window() {
    assert!(ensure_snapshot_compatible("1.12.0", "1.13.1").is_err());
    assert!(ensure_snapshot_compatible("1.13.0", "1.13.1").is_ok());
    assert!(ensure_snapshot_compatible("1.13.0", "1.12.9").is_err());
    assert!(ensure_snapshot_compatible("1.16.0", "1.18.0").is_err());
    assert!(ensure_snapshot_compatible("1.13.2", "1.13.1").is_err());
    assert!(ensure_snapshot_compatible("2.0.0", "1.99.0").is_err());
}

#[test]
fn qdrant_topology_rejects_distributed_or_multi_peer_sources() {
    assert_eq!(
        qdrant_topology_is_standalone(&json!({
            "result": { "status": "disabled" }
        })),
        Some(true)
    );
    assert_eq!(
        qdrant_topology_is_standalone(&json!({
            "result": {
                "status": "enabled",
                "peers": { "1": { "uri": "http://node-1" } }
            }
        })),
        Some(false)
    );
    assert_eq!(
        qdrant_topology_is_standalone(&json!({
            "result": {
                "status": "disabled",
                "peers": {
                    "1": { "uri": "http://node-1" },
                    "2": { "uri": "http://node-2" }
                }
            }
        })),
        Some(false)
    );
}

#[test]
fn qdrant_version_errors_do_not_echo_remote_text() {
    let invalid = "secret-source-version";
    let error = ensure_snapshot_compatible(invalid, "1.13.1").unwrap_err();
    assert!(!error.to_string().contains(invalid));

    let incompatible = "9.0-secret-source-version";
    let error = ensure_snapshot_compatible(incompatible, "1.13.1").unwrap_err();
    assert!(!error.to_string().contains(incompatible));
}

#[test]
fn qdrant_bridge_guard_owns_static_cleanup_state() {
    fn assert_send_static<T: Send + 'static>() {}

    assert_send_static::<QdrantBridge>();
    assert!(std::mem::needs_drop::<QdrantBridge>());
}

#[test]
fn every_attempted_qdrant_mutation_requires_a_process_fence_before_rollback() {
    // A lost upload response can outlive the HTTP future inside Qdrant. Never optimize
    // this to an immediate rollback based only on the client-side error kind.
    assert!(qdrant_rollback_requires_quiescence(true));
    assert!(!qdrant_rollback_requires_quiescence(false));
}

#[test]
fn qdrant_bridge_cleanup_terminates_process_and_removes_every_artifact() {
    let script = qdrant_bridge_stop_script();

    assert!(script.contains("kill -TERM"));
    assert!(script.contains("kill -KILL"));
    assert!(script.contains("/proc/[0-9]*"));
    assert!(script.contains("qdrant_bridge_process_is_owned"));
    assert!(script.contains("qdrant_bridge_expected_start"));
    assert!(script.contains(SOCKET_BRIDGE_CONTAINER_PATH));
    assert!(script.contains(TARGET_BRIDGE_MARKER));
    assert!(script.contains(&sh_quote(TARGET_BRIDGE_SOCKET)));
    assert!(script.contains(&sh_quote(TARGET_BRIDGE_PID)));
    assert!(script.contains(&sh_quote(TARGET_BRIDGE_LOG)));
    assert!(script.contains("rm -f --"));
}

#[test]
fn qdrant_bridge_cleanup_never_trusts_the_pid_file_as_a_signal_target() {
    let script = qdrant_bridge_stop_script();

    assert!(!script.contains(&format!("cat {}", sh_quote(TARGET_BRIDGE_PID))));
    assert!(!script.contains(&format!("< {}", sh_quote(TARGET_BRIDGE_PID))));
    assert!(script.contains("/proc/$qdrant_bridge_candidate/cmdline"));
    assert!(script.contains("--socket"));
    assert!(script.contains("127.0.0.1:6333"));
}

#[test]
fn qdrant_bridge_start_records_its_generation_atomically() {
    let script = qdrant_bridge_start_script();

    assert!(script.contains("qdrant_bridge_process_start_time"));
    assert!(script.contains("printf 'v1 %s %s\\n'"));
    assert!(script.contains("umask 077"));
    assert!(script.contains("set -C"));
    assert!(script.contains(&sh_quote(&format!("{TARGET_BRIDGE_PID}.new"))));
    assert!(script.contains("mv -f --"));
    assert!(script.contains(TARGET_BRIDGE_MARKER));
    assert!(!script.contains(&format!("> {}", sh_quote(TARGET_BRIDGE_LOG))));
}

#[test]
fn an_empty_full_source_is_valid() {
    assert_eq!(
        selected_collections(Vec::new(), &ImportExportSelection::default()).unwrap(),
        Vec::<String>::new()
    );
}

#[test]
fn qdrant_alias_selection_follows_collection_selection() {
    let selected = HashSet::from(["included".to_string()]);
    let aliases = vec![
        qdrant_alias("keep", "included"),
        qdrant_alias("omit", "excluded"),
    ];

    assert_eq!(
        selected_aliases(aliases, &selected),
        vec![qdrant_alias("keep", "included")]
    );
}

#[test]
fn incoming_collection_cannot_resolve_through_a_target_alias() {
    let error = ensure_no_qdrant_name_collisions(
        &HashSet::from(["orders".to_string()]),
        &[],
        &["unrelated".to_string()],
        &[qdrant_alias("orders", "unrelated")],
    )
    .unwrap_err();

    assert!(error.to_string().contains("target alias"));
}

#[test]
fn incoming_alias_cannot_shadow_a_target_collection() {
    let error = ensure_no_qdrant_name_collisions(
        &HashSet::from(["imported".to_string()]),
        &[qdrant_alias("orders", "imported")],
        &["orders".to_string()],
        &[],
    )
    .unwrap_err();

    assert!(error.to_string().contains("target collection"));
}

#[test]
fn source_aliases_replace_conflicts_and_target_aliases_for_replaced_collections() {
    let target = vec![
        qdrant_alias("keep", "untouched"),
        qdrant_alias("conflict", "untouched"),
        qdrant_alias("old", "replaced"),
    ];
    let source = vec![
        qdrant_alias("conflict", "imported"),
        qdrant_alias("source", "imported"),
    ];
    let affected = HashSet::from(["replaced".to_string()]);

    assert_eq!(
        desired_import_aliases(&target, &source, &affected),
        vec![
            qdrant_alias("conflict", "imported"),
            qdrant_alias("keep", "untouched"),
            qdrant_alias("source", "imported"),
        ]
    );
}

#[test]
fn qdrant_alias_actions_exactly_reconcile_in_one_atomic_request() {
    let current = vec![
        qdrant_alias("extra", "old"),
        qdrant_alias("keep", "stable"),
        qdrant_alias("wrong", "old"),
    ];
    let desired = vec![
        qdrant_alias("keep", "stable"),
        qdrant_alias("new", "new_collection"),
        qdrant_alias("wrong", "replacement"),
    ];

    assert_eq!(
        alias_actions(&current, &desired),
        vec![
            json!({ "delete_alias": { "alias_name": "extra" } }),
            json!({ "delete_alias": { "alias_name": "wrong" } }),
            json!({
                "create_alias": {
                    "alias_name": "new",
                    "collection_name": "new_collection"
                }
            }),
            json!({
                "create_alias": {
                    "alias_name": "wrong",
                    "collection_name": "replacement"
                }
            }),
        ]
    );
}

fn qdrant_alias(alias_name: &str, collection_name: &str) -> QdrantAlias {
    QdrantAlias {
        alias_name: alias_name.to_string(),
        collection_name: collection_name.to_string(),
    }
}
