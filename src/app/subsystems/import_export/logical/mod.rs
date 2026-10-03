//! Logical database import/export, transactional rollback, and recovery fencing.

use super::{archive::*, files::*, physical::*, protocol::*, *};

use crate::{databases::engine::EngineFamily, server::credentials::logical_export_env};

pub(super) mod prepared_support;

mod staging;

mod target;

use prepared_support::{
    LogicalApplyError, PreparedLogicalImport, PreparedTarget, apply_prepared_logical_import,
    apply_prepared_logical_imports, cleanup_prepared_logical_import,
    cleanup_prepared_logical_imports, parse_sha256, pin_prepared_source,
};

use staging::LogicalStagingLimits;

pub(super) use staging::{
    UploadLogicalStagingBudget, check_remote_staging_space, physical_staging_bytes,
    upload_logical_staging_budget, upload_physical_staging_bytes,
};

pub(crate) use target::quarantine_uncertain_import;

use target::{
    check_shared_rollback_objects, commit_recovery_manifest, fail_quiesced_setup,
    fence_import_target, quarantine_suffix, restore_import_target_route,
    write_logical_recovery_manifest,
};

mod sources;
pub(super) use sources::*;
mod batch;
use batch::*;
mod dump;
pub(super) use dump::*;
mod backup;
pub(crate) use backup::*;
