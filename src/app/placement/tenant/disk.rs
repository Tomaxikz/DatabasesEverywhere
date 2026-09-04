use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{TenantEngineError, TenantTarget, postgres_sql};
use crate::{
    config::Config,
    disk::{DiskEnforcement, DiskLimitError, DiskLimiter},
    instances::paths::InstancePaths,
    placement::EngineRuntime,
    runtime::docker::DockerRuntime,
    shared::{
        hex::encode_lower,
        limits::{InstanceLimits, mib_to_bytes},
        protocol::Protocol,
        shell::sh_quote,
    },
};

const SOFT_METHOD: &str = "shared_catalog_guard";
const POSTGRES_TENANT_ROOT: &str = "dbev-tenants";
const MYSQL_BOUNDARY_MARKER: &str = ".dbev-quota-boundary";
const POSTGRES_CONTAINER_ROOT: &str = "/var/lib/postgresql/dbev-tenants";
const SOFT_RECOVERY_PERCENT: u64 = 90;

/// Reconciles durable tenant metadata with the boundary the host actually
/// restored. A hard boundary is a one-way safety promise: losing it must keep
/// the tenant fenced instead of silently relabelling the tenant as soft.
pub(crate) fn update_state(
    limits: &mut InstanceLimits,
    disk_limit_blocked: &mut bool,
    enforcement: &DiskEnforcement,
) -> Result<bool, TenantDiskError> {
    check_transition(limits.disk_enforced, enforcement)?;
    let blocked = *disk_limit_blocked && !enforcement.enforced;
    let changed = limits.disk_enforced != enforcement.enforced
        || limits.disk_enforcement_method != enforcement.method
        || *disk_limit_blocked != blocked;
    limits.disk_enforced = enforcement.enforced;
    limits.disk_enforcement_method = enforcement.method.clone();
    *disk_limit_blocked = blocked;
    Ok(changed)
}

/// Validates a proposed boundary without mutating metadata. Resize and
/// migration paths use this before committing a new limit record.
pub(crate) fn check_transition(
    was_hard: bool,
    enforcement: &DiskEnforcement,
) -> Result<(), TenantDiskError> {
    if was_hard && !enforcement.enforced {
        return Err(TenantDiskError::HardQuotaLost);
    }
    Ok(())
}

/// Returns the durable blocked state for a catalog-enforced tenant. Once a
/// tenant is blocked it must fall below the recovery watermark before being
/// reopened, preventing fence/unfence churn around the exact limit.
pub(crate) fn soft_limit_blocked(used_bytes: u64, disk_mib: u64, already_blocked: bool) -> bool {
    let limit_bytes = mib_to_bytes(disk_mib);
    if already_blocked {
        let recovery_bytes = limit_bytes.saturating_mul(SOFT_RECOVERY_PERCENT) / 100;
        used_bytes > recovery_bytes
    } else {
        used_bytes >= limit_bytes
    }
}

pub(crate) fn soft_limit_bytes(disk_mib: u64) -> (u64, u64) {
    let limit_bytes = mib_to_bytes(disk_mib);
    let recovery_bytes = limit_bytes.saturating_mul(SOFT_RECOVERY_PERCENT) / 100;
    (limit_bytes, recovery_bytes)
}

/// Creates protocol storage that must exist before the engine creates the
/// tenant database. PostgreSQL uses a daemon-owned tablespace so all relation
/// files have one durable filesystem boundary. Other engines create their
/// schema directory themselves and are finalized by [`set_limit`].
pub(crate) async fn prepare(
    config: &Config,
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    disk_mib: u64,
) -> Result<(), TenantDiskError> {
    if runtime.protocol != Protocol::Postgres {
        return Ok(());
    }

    let boundary = boundary(config, runtime, target)?;
    let live = live_boundary(config, runtime, &boundary)?;
    docker
        .verify_data_bind(runtime.protocol, &runtime.runtime_id, &live.root)
        .await?;
    let container_path = postgres_container_path(&boundary.key);
    let command = postgres_storage_script(&container_path);
    docker
        .exec_tenant_shell(
            Protocol::Postgres,
            &runtime.runtime_id,
            &command,
            &[],
            std::time::Duration::from_secs(30),
        )
        .await?;

    // Create through the source that is actually mounted into the pool. This
    // matters for FuseQuota: writing its raw backing directory bypasses the
    // helper's namespace/cache and the new path may not exist in the
    // container. The raw path must still resolve to the same real directory,
    // because native child quotas are deliberately attached there.
    require_dir_chain(&live.root, &live.path).await?;
    if live.path != boundary.path {
        require_dir_chain(&boundary.root, &boundary.path).await?;
    }
    set_boundary_limit(config, &boundary, disk_mib).await?;

    let output = postgres_sql(
        docker,
        runtime,
        crate::databases::postgres::docker::CONTROL_DATABASE,
        &crate::databases::postgres::provision::ensure_tenant_tablespace_sql(
            target.database,
            &container_path,
        ),
    )
    .await?;
    let actual = one_line(&output.stdout, "PostgreSQL tablespace location")?;
    if actual != container_path {
        return Err(TenantDiskError::StorageIdentity(format!(
            "PostgreSQL tablespace for {} resolves to {actual:?}, expected {container_path:?}",
            target.database
        )));
    }
    Ok(())
}

/// Applies or restores the tenant's disk boundary. Unsupported physical
/// layouts keep the catalog guard and never claim hard enforcement.
pub(crate) async fn set_limit(
    config: &Config,
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    disk_mib: u64,
) -> Result<DiskEnforcement, TenantDiskError> {
    let boundary = match runtime.protocol {
        Protocol::Postgres => {
            let output = postgres_sql(
                docker,
                runtime,
                crate::databases::postgres::docker::CONTROL_DATABASE,
                &crate::databases::postgres::provision::tenant_tablespace_location_sql(
                    target.database,
                ),
            )
            .await?;
            let expected = postgres_container_path(&storage_key(target.database));
            let actual = output.stdout.trim();
            if actual != expected {
                // Existing pools created before per-tenant tablespaces stay on
                // the catalog guard until migrated; never relabel PGDATA/base.
                return Ok(soft_enforcement());
            }
            boundary(config, runtime, target)?
        }
        Protocol::Mysql | Protocol::Mariadb => {
            let boundary = boundary(config, runtime, target)?;
            let live = live_boundary(config, runtime, &boundary)?;
            ensure_mysql_marker(&live.root, &live.path).await?;
            if live.path != boundary.path {
                require_dir_chain(&boundary.root, &boundary.path).await?;
                require_mysql_marker(&boundary.path).await?;
            }
            boundary
        }
        Protocol::Mongodb | Protocol::Clickhouse => {
            return Ok(soft_enforcement());
        }
        protocol => return Err(TenantDiskError::Unsupported(protocol)),
    };
    set_boundary_limit(config, &boundary, disk_mib).await
}

/// Reads the authoritative kernel project-quota counter for a hard-enforced
/// tenant. This never traverses tenant files, includes charged-but-unlinked
/// inodes, and is suitable for shrink admission and periodic telemetry.
/// Soft/catalog-only layouts are rejected.
pub(crate) async fn quota_usage_bytes(
    config: &Config,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<u64, TenantDiskError> {
    if !uses_path_boundary(runtime.protocol) {
        return Err(TenantDiskError::Unsupported(runtime.protocol));
    }
    let boundary = boundary(config, runtime, target)?;
    limiter(config)
        .path_quota_usage_bytes(
            &boundary.owner,
            &boundary.path,
            &project_registry_root(config),
        )
        .await
        .map_err(TenantDiskError::from)
}

/// Removes the marker that prevents a MySQL-family tenant from dropping and
/// recreating its schema directory outside the assigned project. Call only
/// after the gateway and engine account have been fenced and sessions drained.
pub(crate) async fn prepare_drop(
    config: &Config,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<(), TenantDiskError> {
    if matches!(runtime.protocol, Protocol::Mysql | Protocol::Mariadb) {
        let boundary = boundary(config, runtime, target)?;
        let live = live_boundary(config, runtime, &boundary)?;
        remove_mysql_marker(&live.path).await?;
        if live.path != boundary.path {
            require_absent(&boundary.path.join(MYSQL_BOUNDARY_MARKER)).await?;
        }
    }
    Ok(())
}

/// Tears down the host quota after the engine database has been removed. The
/// project-ID claim is intentionally retained as a tombstone, preventing an
/// uncertain old quota from ever being reassigned to another tenant.
pub(crate) async fn remove(
    config: &Config,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<(), TenantDiskError> {
    if !uses_path_boundary(runtime.protocol) {
        return Ok(());
    }
    let boundary = boundary(config, runtime, target)?;
    let live = live_boundary(config, runtime, &boundary)?;
    // The engine drop must have removed the boundary, or left only an empty
    // directory behind, before quota state is changed. Recreating a missing
    // MySQL-family directory here would inherit the shared pool project and
    // make strict project cleanup reject an otherwise successful drop.
    // Accepting a non-empty directory would be worse: clearing its labels and
    // releasing the project would leave tenant data outside its hard cap.
    remove_empty_boundary(&live.path).await?;
    if live.path != boundary.path {
        require_absent(&boundary.path).await?;
    }
    limiter(config)
        .remove_path_quota(
            &boundary.owner,
            &boundary.path,
            &project_registry_root(config),
        )
        .await?;
    Ok(())
}

pub(crate) fn owner_id(runtime: &EngineRuntime, target: TenantTarget<'_>) -> String {
    format!(
        "shared:{}:{}:{}",
        runtime.protocol.as_str(),
        runtime.runtime_id,
        storage_key(target.database)
    )
}

fn uses_path_boundary(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Postgres | Protocol::Mysql | Protocol::Mariadb
    )
}

struct Boundary {
    owner: String,
    root: PathBuf,
    path: PathBuf,
    key: String,
}

struct LiveBoundary {
    root: PathBuf,
    path: PathBuf,
}

fn boundary(
    config: &Config,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<Boundary, TenantDiskError> {
    let paths = InstancePaths::new(&config.paths, &runtime.runtime_id)
        .map_err(|error| TenantDiskError::StorageIdentity(error.to_string()))?;
    let key = storage_key(target.database);
    let path = match runtime.protocol {
        Protocol::Postgres => paths.data.join(POSTGRES_TENANT_ROOT).join(&key),
        Protocol::Mysql | Protocol::Mariadb => paths.data.join(mysql_filename(target.database)?),
        Protocol::Mongodb | Protocol::Clickhouse => paths.data.join("dbev-soft-tenants").join(&key),
        protocol => return Err(TenantDiskError::Unsupported(protocol)),
    };
    check_relative_child(&paths.data, &path)?;
    Ok(Boundary {
        owner: owner_id(runtime, target),
        root: paths.data,
        path,
        key,
    })
}

fn live_boundary(
    config: &Config,
    runtime: &EngineRuntime,
    boundary: &Boundary,
) -> Result<LiveBoundary, TenantDiskError> {
    live_boundary_for_method(config, &runtime.limits.disk_enforcement_method, boundary)
}

fn live_boundary_for_method(
    config: &Config,
    persisted_method: &str,
    boundary: &Boundary,
) -> Result<LiveBoundary, TenantDiskError> {
    let relative = boundary.path.strip_prefix(&boundary.root).map_err(|_| {
        TenantDiskError::StorageIdentity(format!(
            "tenant storage {} escapes shared root {}",
            boundary.path.display(),
            boundary.root.display()
        ))
    })?;
    let root = limiter(config)
        .for_persisted_method(persisted_method)
        .container_data_path(&boundary.root)?;
    let path = root.join(relative);
    check_relative_child(&root, &path)?;
    Ok(LiveBoundary { root, path })
}

async fn set_boundary_limit(
    config: &Config,
    boundary: &Boundary,
    disk_mib: u64,
) -> Result<DiskEnforcement, TenantDiskError> {
    create_real_dir(&project_registry_root(config)).await?;
    let enforcement = limiter(config)
        .apply_path_quota(
            &boundary.owner,
            &boundary.path,
            &project_registry_root(config),
            disk_mib,
        )
        .await?;
    if !enforcement.enforced {
        return Ok(soft_enforcement());
    }
    Ok(enforcement)
}

fn soft_enforcement() -> DiskEnforcement {
    DiskEnforcement {
        enforced: false,
        method: SOFT_METHOD.to_string(),
        container_data_path: None,
    }
}

fn limiter(config: &Config) -> DiskLimiter {
    DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
}

fn project_registry_root(config: &Config) -> PathBuf {
    PathBuf::from(config.paths.volumes_root())
}

fn storage_key(database: &str) -> String {
    encode_lower(&Sha256::digest(database.as_bytes())[..16])
}

fn postgres_container_path(key: &str) -> String {
    format!("{POSTGRES_CONTAINER_ROOT}/{key}")
}

fn postgres_storage_script(container_path: &str) -> String {
    let root = sh_quote(POSTGRES_CONTAINER_ROOT);
    let path = sh_quote(container_path);
    format!(
        "set -u\n\
         umask 077\n\
         root={root}\n\
         path={path}\n\
         fail() {{\n\
           status=\"$1\"\n\
           step=\"$2\"\n\
           failed_path=\"$3\"\n\
           printf 'postgres tenant storage failed: step=%s path=%s exit=%s\\n' \"$step\" \"$failed_path\" \"$status\" >&2\n\
           exit \"$status\"\n\
         }}\n\
         if [ -L \"$root\" ]; then fail 70 validate_root \"$root\"; fi\n\
         if [ -e \"$root\" ]; then\n\
           if [ ! -d \"$root\" ]; then fail 71 validate_root \"$root\"; fi\n\
         elif mkdir \"$root\"; then :; else status=$?; fail \"$status\" create_root \"$root\"; fi\n\
         if chmod 0700 \"$root\"; then :; else status=$?; fail \"$status\" chmod_root \"$root\"; fi\n\
         if [ -L \"$path\" ]; then fail 72 validate_tenant \"$path\"; fi\n\
         if [ -e \"$path\" ]; then\n\
           if [ ! -d \"$path\" ]; then fail 73 validate_tenant \"$path\"; fi\n\
         elif mkdir \"$path\"; then :; else status=$?; fail \"$status\" create_tenant \"$path\"; fi\n\
         if chmod 0700 \"$path\"; then :; else status=$?; fail \"$status\" chmod_tenant \"$path\"; fi"
    )
}

/// MySQL maps punctuation to @hhhh in schema-directory names. DBE's public
/// identifier policy permits only ASCII letters, digits, underscore, and dash,
/// so dash is the only byte requiring filename encoding here.
fn mysql_filename(database: &str) -> Result<String, TenantDiskError> {
    if database.is_empty()
        || !database
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(TenantDiskError::StorageIdentity(
            "database name is outside the managed MySQL filename policy".to_string(),
        ));
    }
    Ok(database.replace('-', "@002d"))
}

fn check_relative_child(root: &Path, path: &Path) -> Result<(), TenantDiskError> {
    let relative = path.strip_prefix(root).map_err(|_| {
        TenantDiskError::StorageIdentity(format!(
            "tenant storage {} escapes shared root {}",
            path.display(),
            root.display()
        ))
    })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(TenantDiskError::StorageIdentity(format!(
            "tenant storage path {} is not a strict relative child",
            path.display()
        )));
    }
    Ok(())
}

async fn create_real_dir(path: &Path) -> Result<(), TenantDiskError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|source| io_error(path, source))?;
    require_real_dir(path).await
}

async fn require_real_dir(path: &Path) -> Result<(), TenantDiskError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TenantDiskError::StorageIdentity(format!(
            "tenant storage boundary {} must be a real directory",
            path.display()
        )));
    }
    Ok(())
}

async fn require_dir_chain(root: &Path, path: &Path) -> Result<(), TenantDiskError> {
    require_real_dir(root).await?;
    let relative = path.strip_prefix(root).map_err(|_| {
        TenantDiskError::StorageIdentity(format!(
            "tenant storage {} escapes shared root {}",
            path.display(),
            root.display()
        ))
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(TenantDiskError::StorageIdentity(format!(
                "tenant storage path {} is not a strict relative child",
                path.display()
            )));
        };
        current.push(component);
        let metadata = tokio::fs::symlink_metadata(&current)
            .await
            .map_err(|source| io_error(&current, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(TenantDiskError::StorageIdentity(format!(
                "tenant storage component {} must be a real directory",
                current.display()
            )));
        }
    }
    Ok(())
}

async fn ensure_dir_chain(root: &Path, path: &Path) -> Result<(), TenantDiskError> {
    create_real_dir(root).await?;
    let relative = path.strip_prefix(root).map_err(|_| {
        TenantDiskError::StorageIdentity(format!(
            "tenant storage {} escapes shared root {}",
            path.display(),
            root.display()
        ))
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(TenantDiskError::StorageIdentity(format!(
                "tenant storage path {} is not a strict relative child",
                path.display()
            )));
        };
        current.push(component);
        match tokio::fs::create_dir(&current).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(io_error(&current, source)),
        }
        let metadata = tokio::fs::symlink_metadata(&current)
            .await
            .map_err(|source| io_error(&current, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(TenantDiskError::StorageIdentity(format!(
                "tenant storage component {} must be a real directory",
                current.display()
            )));
        }
    }
    Ok(())
}

async fn ensure_mysql_marker(root: &Path, path: &Path) -> Result<(), TenantDiskError> {
    ensure_dir_chain(root, path).await?;
    let marker = path.join(MYSQL_BOUNDARY_MARKER);
    match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .await
    {
        Ok(file) => {
            file.sync_all()
                .await
                .map_err(|source| io_error(&marker, source))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o400))
                    .await
                    .map_err(|source| io_error(&marker, source))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            require_mysql_marker(path).await?;
        }
        Err(source) => return Err(io_error(&marker, source)),
    }
    Ok(())
}

async fn require_mysql_marker(path: &Path) -> Result<(), TenantDiskError> {
    let marker = path.join(MYSQL_BOUNDARY_MARKER);
    let metadata = tokio::fs::symlink_metadata(&marker)
        .await
        .map_err(|source| io_error(&marker, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 0 {
        return Err(TenantDiskError::StorageIdentity(format!(
            "MySQL quota marker {} is not an empty regular file",
            marker.display()
        )));
    }
    Ok(())
}

async fn remove_mysql_marker(path: &Path) -> Result<(), TenantDiskError> {
    let marker = path.join(MYSQL_BOUNDARY_MARKER);
    match tokio::fs::remove_file(&marker).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(&marker, source)),
    }
}

async fn remove_empty_boundary(path: &Path) -> Result<(), TenantDiskError> {
    match tokio::fs::remove_dir(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

async fn require_absent(path: &Path) -> Result<(), TenantDiskError> {
    match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
        Ok(_) => Err(TenantDiskError::StorageIdentity(format!(
            "tenant storage {} remained in the raw backing directory after the live quota path was removed",
            path.display()
        ))),
    }
}

fn one_line<'a>(value: &'a str, field: &str) -> Result<&'a str, TenantDiskError> {
    let mut lines = value.lines().map(str::trim).filter(|line| !line.is_empty());
    let line = lines.next().ok_or_else(|| {
        TenantDiskError::StorageIdentity(format!("{field} was not returned by the engine"))
    })?;
    if lines.next().is_some() {
        return Err(TenantDiskError::StorageIdentity(format!(
            "{field} returned more than one row"
        )));
    }
    Ok(line)
}

fn io_error(path: &Path, source: std::io::Error) -> TenantDiskError {
    TenantDiskError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TenantDiskError {
    #[error("{0} cannot use shared tenant storage")]
    Unsupported(Protocol),
    #[error("shared tenant storage identity is invalid: {0}")]
    StorageIdentity(String),
    #[error("shared tenant storage path {path} failed: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("shared tenant disk limiter failed: {0}")]
    Disk(#[from] DiskLimitError),
    #[error("an existing hard tenant disk quota could not be restored")]
    HardQuotaLost,
    #[error("shared tenant engine operation failed: {0}")]
    Engine(#[from] TenantEngineError),
    #[error("shared tenant container operation failed: {0}")]
    Docker(#[from] crate::runtime::docker::DockerError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_filename_mapping_matches_server_rules_for_managed_names() {
        assert_eq!(mysql_filename("tenant_db").unwrap(), "tenant_db");
        assert_eq!(
            mysql_filename("tenant-db-1").unwrap(),
            "tenant@002ddb@002d1"
        );
        assert!(mysql_filename("tenant.db").is_err());
    }

    #[test]
    fn storage_keys_are_stable_and_path_safe() {
        let first = storage_key("tenant-a");
        assert_eq!(first, storage_key("tenant-a"));
        assert_ne!(first, storage_key("tenant-b"));
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn hard_quota_never_silently_downgrades() {
        let mut limits = InstanceLimits {
            disk_enforced: true,
            disk_enforcement_method: "host_xfs_project_quota".to_string(),
            ..InstanceLimits::default()
        };
        let mut blocked = false;
        let soft = soft_enforcement();

        assert!(update_state(&mut limits, &mut blocked, &soft).is_err());
        assert!(limits.disk_enforced);
        assert_eq!(limits.disk_enforcement_method, "host_xfs_project_quota");
    }

    #[test]
    fn soft_limit_recovery_has_hysteresis() {
        let mib = 1024 * 1024;
        assert!(!soft_limit_blocked(99 * mib, 100, false));
        assert!(soft_limit_blocked(100 * mib, 100, false));
        assert!(soft_limit_blocked(91 * mib, 100, true));
        assert!(!soft_limit_blocked(90 * mib, 100, true));
    }

    #[test]
    fn strict_child_check_rejects_escape_and_root_alias() {
        let root = Path::new("/srv/dbev/pool");
        assert!(check_relative_child(root, Path::new("/srv/dbev/pool/tenant/a")).is_ok());
        assert!(check_relative_child(root, root).is_err());
        assert!(check_relative_child(root, Path::new("/srv/dbev/pool/../other")).is_err());
    }

    #[test]
    fn postgres_container_paths_never_include_public_identifiers() {
        let key = storage_key("customer-secret-name");
        let path = postgres_container_path(&key);
        assert!(path.starts_with("/var/lib/postgresql/dbev-tenants/"));
        assert!(!path.contains("customer"));
    }

    #[test]
    fn postgres_storage_setup_inherits_the_numeric_runtime_user() {
        let path = postgres_container_path(&storage_key("tenant-a"));
        let script = postgres_storage_script(&path);

        assert!(!script.contains("chown"));
        assert!(!script.contains("postgres:postgres"));
        assert!(!script.contains("mkdir -p"));
        assert!(script.contains("create_root"));
        assert!(script.contains("create_tenant"));
        assert!(script.contains("chmod_tenant"));
        assert!(script.contains("step=%s path=%s exit=%s"));
        assert!(script.contains(&path));
    }

    #[test]
    fn persisted_pool_method_selects_raw_or_fuse_visible_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let raw_root = temp.path().join("volumes").join("pool-postgres-a");
        let raw_path = raw_root
            .join(POSTGRES_TENANT_ROOT)
            .join(storage_key("tenant-a"));
        let boundary = Boundary {
            owner: "test-owner".to_string(),
            root: raw_root.clone(),
            path: raw_path.clone(),
            key: storage_key("tenant-a"),
        };
        let mut config = Config::default();
        config.paths.fuse = temp.path().join("fuse").display().to_string();
        config.disk.mode = crate::config::DiskLimitMode::SoftScanner;

        let fuse = live_boundary_for_method(&config, "fuse_quota", &boundary).unwrap();
        assert_ne!(fuse.root, raw_root);
        assert!(fuse.root.starts_with(temp.path().join("fuse/instances")));
        assert_eq!(
            fuse.path.strip_prefix(&fuse.root).unwrap(),
            raw_path.strip_prefix(&raw_root).unwrap()
        );

        config.disk.mode = crate::config::DiskLimitMode::FuseQuota;
        for method in ["soft_scanner", "host_xfs_project_quota"] {
            let live = live_boundary_for_method(&config, method, &boundary).unwrap();
            assert_eq!(live.root, raw_root, "persisted method {method}");
            assert_eq!(live.path, raw_path, "persisted method {method}");
        }
    }

    #[tokio::test]
    async fn validation_never_creates_a_missing_raw_backing_path() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("pool");
        let path = root.join(POSTGRES_TENANT_ROOT).join("missing");
        std::fs::create_dir(&root).unwrap();

        let error = require_dir_chain(&root, &path).await.unwrap_err();

        assert!(matches!(error, TenantDiskError::Io { .. }));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn missing_boundary_is_accepted_without_recreation() {
        let temp = tempfile::tempdir().unwrap();
        let boundary = temp.path().join("dropped-tenant");

        remove_empty_boundary(&boundary).await.unwrap();

        assert!(!boundary.exists());
    }

    #[tokio::test]
    async fn empty_boundary_is_removed_before_quota_teardown() {
        let temp = tempfile::tempdir().unwrap();
        let boundary = temp.path().join("empty-tenant");
        std::fs::create_dir(&boundary).unwrap();

        remove_empty_boundary(&boundary).await.unwrap();

        assert!(!boundary.exists());
    }

    #[tokio::test]
    async fn nonempty_boundary_fails_closed_and_preserves_data() {
        let temp = tempfile::tempdir().unwrap();
        let boundary = temp.path().join("tenant-with-data");
        std::fs::create_dir(&boundary).unwrap();
        std::fs::write(boundary.join("keep"), b"tenant data").unwrap();

        let error = remove_empty_boundary(&boundary).await.unwrap_err();

        assert!(matches!(error, TenantDiskError::Io { .. }));
        assert_eq!(
            std::fs::read(boundary.join("keep")).unwrap(),
            b"tenant data"
        );
    }
}
