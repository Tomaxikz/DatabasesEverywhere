//! Save a reference run with `cargo bench --locked --profile local --bench route_lookup -- --save-baseline indexed-routes`.
//! Repeat with `--baseline indexed-routes` to compare against it on the same host.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use databases_everywhere::{
    server::{
        metadata::{InstanceMetadata, SCHEMA_VERSION},
        state::{DatabaseRouteResolution, InstanceStore},
    },
    utils::limits::InstanceLimits,
};
use serde_json::json;
use tokio::runtime::Builder;

async fn route_store(routes: usize) -> InstanceStore {
    let tenants = (0..routes)
        .map(|index| {
            let username = match index {
                0 | 1 => "shared_username".to_owned(),
                _ => format!("user_{index}"),
            };
            serde_json::from_value::<InstanceMetadata>(json!({
                "schema_version": SCHEMA_VERSION,
                "instance_id": format!("instance_{index}"),
                "protocol": "postgres",
                "status": "running",
                "public": { "host": "localhost", "port": 5432 },
                "backend": {
                    "kind": "unix_socket",
                    "socket_path": format!("/run/dbev/instance_{index}/.s.PGSQL.5432")
                },
                "runtime": {
                    "kind": "docker",
                    "container_name": format!("postgres_{index}"),
                    "network_mode": "none"
                },
                "database": { "name": format!("db_{index}"), "username": username },
                "limits": InstanceLimits::default(),
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            }))
            .expect("valid benchmark instance")
        })
        .collect();
    let store = InstanceStore::default();
    store.replace_all(tenants).await;
    store
}

fn route_lookup(c: &mut Criterion) {
    let runtime = Builder::new_current_thread()
        .build()
        .expect("build should succeed");
    let mut group = c.benchmark_group("postgres_route_without_database");
    for count in [100, 1_000, 5_000] {
        let store = runtime.block_on(route_store(count));
        let unique = format!("user_{}", count - 1);
        assert!(matches!(
            runtime.block_on(store.resolve_postgres(&unique, None)),
            DatabaseRouteResolution::Found { .. }
        ));
        assert!(matches!(
            runtime.block_on(store.resolve_postgres("shared_username", None)),
            DatabaseRouteResolution::Ambiguous
        ));

        for (case, username) in [
            ("unique", unique.as_str()),
            ("ambiguous", "shared_username"),
        ] {
            group.bench_function(BenchmarkId::new(case, count), |b| {
                b.to_async(&runtime)
                    .iter(|| store.resolve_postgres(black_box(username), None));
            });
        }
    }
    group.finish();
}

criterion_group!(benches, route_lookup);
criterion_main!(benches);
