//! Extends the existing disposable-engine matrix through production transfers.
use crate::{
    api::{http::router::AppState, import_export::logical, test_support},
    config::Config,
    instances::{metadata::InstanceMetadata, test_support::metadata},
    placement::{DeploymentMode, EngineRuntime, ReserveTenant},
    runtime::docker::DockerRuntime,
    shared::limits::InstanceLimits,
};

pub(crate) async fn shared_roundtrip(
    config: &Config,
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    limits: &InstanceLimits,
    tenants: [(&str, &str, &str); 2],
    mutate: impl std::future::Future<Output = ()>,
) {
    let (offline, storage) = test_support::database(config.clone()).await;
    let mut data = (*offline).clone();
    data.docker = docker.clone();
    let state = AppState::new(data);
    let mut runtime = runtime.clone();
    let attestation = crate::placement::runtime::probe_compatibility(docker, &runtime)
        .await
        .unwrap();
    runtime.database_version = Some(attestation.version);
    runtime.compatibility = Some(attestation.compatibility);
    state.placements.save(&runtime).await.unwrap();
    let mut instances: Vec<InstanceMetadata> = Vec::new();
    for (index, (database, username, password)) in tenants.into_iter().enumerate() {
        let id = format!("transfer_tenant_{index}");
        let mut instance = metadata(&id, runtime.protocol);
        instance.deployment_mode = DeploymentMode::Shared;
        instance.runtime_id = runtime.runtime_id.clone();
        instance.owner = runtime.owner.clone();
        instance.backend = runtime.backend.clone();
        instance.runtime = runtime.runtime.clone();
        instance.database.name = database.into();
        instance.database.username = username.into();
        instance.tenant_password = Some(password.into());
        instance.limits = limits.clone();
        state
            .placements
            .reserve(ReserveTenant {
                owner: runtime.owner.clone().unwrap(),
                instance_id: &id,
                runtime_id: &runtime.runtime_id,
                database,
                username,
                limits,
            })
            .await
            .unwrap();
        state.placements.mark_provisioned(&id).await.unwrap();
        state.manager.upsert(instance.clone()).await.unwrap();
        instances.push(instance);
    }
    let target = &instances[0];
    let _tenant = state.instance_locks.lock(&target.instance_id).await;
    let _pool = state.instance_locks.lock(target.runtime_id()).await;
    let artifact = storage.path().join(format!(
        "roundtrip.{}",
        super::files::dump_extension(runtime.protocol)
    ));
    // Same logical paths used by exports and shared backup/restore endpoints.
    // Keep the original data recoverable until this fixture is torn down.
    const MAX_BYTES: u64 = 16 * 1024 * 1024;
    let before = docker
        .verified_container_identity(runtime.protocol, &runtime.runtime_id)
        .await
        .unwrap();
    assert!(before.is_some());
    logical::create_shared_backup(&state, target, artifact.clone(), MAX_BYTES)
        .await
        .expect("export the target tenant through the production backup path");
    assert!(std::fs::metadata(&artifact).unwrap().len() > 0);
    mutate.await;
    logical::restore_shared_backup(&state, target, &artifact, MAX_BYTES, MAX_BYTES)
        .await
        .expect("restore only the target tenant through the production rollback-safe path");
    assert!(
        !state
            .instances
            .routes_fenced(&instances[1].instance_id)
            .await,
        "restoring A must not fence B"
    );
    assert_eq!(
        docker
            .inspect_instance(runtime.protocol, &runtime.runtime_id)
            .await
            .unwrap()
            .status,
        crate::runtime::docker::DockerContainerStatus::Running
    );
    assert_eq!(
        docker
            .verified_container_identity(runtime.protocol, &runtime.runtime_id)
            .await
            .unwrap(),
        before,
        "restoring A must not replace or restart its pool"
    );
}
