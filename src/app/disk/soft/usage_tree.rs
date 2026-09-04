//! Transactional usage cache for inotify-driven partial scans.
//! Notifications are hints; updates are root-relative and publish atomically.
//! Periodic full scans remain authoritative.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    ffi::{OsStr, OsString},
    io::{Error, ErrorKind},
    path::{Component, Path, PathBuf},
    time::Instant,
};

use rustix::{
    fd::OwnedFd,
    fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, fstat, open, openat, statat},
    io::{Errno, fcntl_dupfd_cloexec},
};

pub(crate) use crate::disk::usage::DirectoryIdentity as RootIdentity;
use crate::disk::usage::{DirectoryUsage, ScanLimits};

const ALLOCATION_BLOCK_BYTES: u64 = 512;
const CACHE_DIRECTORY_LIMIT_MESSAGE: &str = "usage-tree directory cache limit exceeded";

/// Open `path` without following its final component and return its identity.
pub(crate) fn root_identity(path: &Path) -> Result<RootIdentity, Error> {
    let (directory, identity, _) = open_root(path)?;
    drop(directory);
    Ok(identity)
}

/// A full baseline with directory-level aggregates bound to a target fingerprint.
#[derive(Debug)]
pub(crate) struct UsageTreeCache {
    root_identity: RootIdentity,
    target_generation: String,
    max_cached_directories: usize,
    nodes: HashMap<PathBuf, CachedDirectory>,
}

/// A bounded tree result; capped trees must fall back to streaming scans.
#[derive(Debug)]
pub(crate) enum BoundedFullScan {
    Cached(UsageTreeCache),
    DirectoryLimitExceeded,
}

#[derive(Debug)]
struct CachedDirectory {
    /// This directory plus its immediate non-directory entries.
    base: DirectoryUsage,
    total: DirectoryUsage,
    children: BTreeSet<OsString>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReconcileError {
    /// The hint is ambiguous and requires a full scan.
    #[error("full disk reconciliation required: {0}")]
    FullScanRequired(String),
    #[error("partial disk reconciliation failed: {0}")]
    Io(#[source] Error),
}

impl ReconcileError {
    pub(crate) fn requires_full_scan(&self) -> bool {
        matches!(self, Self::FullScanRequired(_))
    }

    fn full(reason: impl Into<String>) -> Self {
        Self::FullScanRequired(reason.into())
    }
}

impl From<Error> for ReconcileError {
    fn from(error: Error) -> Self {
        Self::Io(error)
    }
}

impl UsageTreeCache {
    /// Build an authoritative baseline.
    #[cfg(test)]
    pub(crate) fn scan_full(
        root: &Path,
        target_generation: String,
        limits: ScanLimits,
    ) -> Result<Self, Error> {
        match Self::scan_full_bounded(root, target_generation, limits, usize::MAX)? {
            BoundedFullScan::Cached(cache) => Ok(cache),
            BoundedFullScan::DirectoryLimitExceeded => {
                unreachable!("an unbounded usage-tree scan exceeded its directory limit")
            }
        }
    }

    /// Build a cache bounded by `max_cached_directories`.
    pub(crate) fn scan_full_bounded(
        root: &Path,
        target_generation: String,
        limits: ScanLimits,
        max_cached_directories: usize,
    ) -> Result<BoundedFullScan, Error> {
        if max_cached_directories == 0 {
            return Ok(BoundedFullScan::DirectoryLimitExceeded);
        }
        let (root_fd, opened_identity, root_stat) = open_root(root)?;
        let mut budget = ScanBudget::new(limits);
        let mut nodes = HashMap::new();
        let result = scan_directory_tree(
            &root_fd,
            &root_stat,
            Path::new(""),
            0,
            &mut budget,
            &mut nodes,
            max_cached_directories,
        );
        if let Err(error) = result {
            if is_cache_directory_limit_error(&error) {
                return Ok(BoundedFullScan::DirectoryLimitExceeded);
            }
            return Err(error);
        }
        validate_complete_tree(&nodes, limits)?;
        if root_identity(root)? != opened_identity {
            return Err(Error::other(
                "the data directory was replaced during the full disk scan",
            ));
        }
        Ok(BoundedFullScan::Cached(Self {
            root_identity: opened_identity,
            target_generation,
            max_cached_directories,
            nodes,
        }))
    }

    pub(crate) fn usage(&self) -> DirectoryUsage {
        self.nodes
            .get(Path::new(""))
            .map_or_else(DirectoryUsage::default, |root| root.total)
    }

    pub(crate) fn directory_count(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn root_identity(&self) -> RootIdentity {
        self.root_identity
    }

    /// Reconcile clean, relative dirty subtrees as one transaction.
    pub(crate) fn reconcile(
        &mut self,
        root: &Path,
        target_generation: &str,
        changed_paths: &[PathBuf],
        limits: ScanLimits,
    ) -> Result<DirectoryUsage, ReconcileError> {
        if target_generation != self.target_generation {
            return Err(ReconcileError::full(
                "the target generation no longer matches the cached baseline",
            ));
        }
        let (root_fd, current_identity, _) = open_root(root).map_err(ReconcileError::Io)?;
        if current_identity != self.root_identity {
            return Err(ReconcileError::full(
                "the data directory was replaced at the same pathname",
            ));
        }
        if !self.nodes.contains_key(Path::new("")) {
            return Err(ReconcileError::full(
                "the cached usage tree has no root node",
            ));
        }
        if changed_paths.is_empty() {
            return Ok(self.usage());
        }

        let mut budget = ScanBudget::new(limits);
        let candidates = self.plan_candidates(&root_fd, changed_paths, &mut budget)?;
        let mut staged = Vec::with_capacity(candidates.len());
        let mut staged_directory_count = 0_usize;
        for candidate in candidates {
            budget.check()?;
            let directory = match open_relative_directory(&root_fd, &candidate) {
                Ok(directory) => directory,
                Err(OpenRelativeError::Unavailable) => {
                    return Err(ReconcileError::full(
                        "a dirty subtree changed while it was being scanned",
                    ));
                }
                Err(OpenRelativeError::Io(error)) => return Err(ReconcileError::Io(error)),
            };
            let stat = fstat(&directory)
                .map_err(Error::from)
                .map_err(ReconcileError::Io)?;
            let identity = identity_from_stat(&stat).map_err(ReconcileError::Io)?;
            if identity == self.root_identity && !candidate.as_os_str().is_empty() {
                return Err(ReconcileError::full(
                    "a dirty subtree unexpectedly resolves to the scan root",
                ));
            }
            let mut replacement = HashMap::new();
            let remaining_staging_capacity = self
                .max_cached_directories
                .checked_sub(staged_directory_count)
                .ok_or_else(|| {
                    ReconcileError::full(
                        "the cumulative incremental cache directory bound was exceeded while staging dirty subtrees",
                    )
                })?;
            if remaining_staging_capacity == 0 {
                return Err(ReconcileError::full(
                    "the cumulative incremental cache directory bound was exceeded while staging dirty subtrees",
                ));
            }
            scan_directory_tree(
                &directory,
                &stat,
                &candidate,
                component_count(&candidate),
                &mut budget,
                &mut replacement,
                remaining_staging_capacity,
            )
            .map_err(|error| {
                if is_cache_directory_limit_error(&error) {
                    ReconcileError::full(
                        "the cumulative incremental cache directory bound was exceeded while staging dirty subtrees",
                    )
                } else {
                    ReconcileError::Io(error)
                }
            })?;
            staged_directory_count = staged_directory_count
                .checked_add(replacement.len())
                .ok_or_else(|| {
                    ReconcileError::full(
                        "the cumulative incremental cache directory count overflowed",
                    )
                })?;
            debug_assert!(staged_directory_count <= self.max_cached_directories);
            staged.push((candidate, replacement));
        }

        if root_identity(root).map_err(ReconcileError::Io)? != self.root_identity {
            return Err(ReconcileError::full(
                "the data directory was replaced during partial reconciliation",
            ));
        }

        self.commit_replacements(staged, limits)
    }

    fn plan_candidates(
        &self,
        root_fd: &OwnedFd,
        changed_paths: &[PathBuf],
        budget: &mut ScanBudget,
    ) -> Result<Vec<PathBuf>, ReconcileError> {
        let mut candidates = Vec::with_capacity(changed_paths.len());
        for changed_path in changed_paths {
            budget.check()?;
            validate_changed_path(changed_path)?;
            candidates.push(self.nearest_cached_existing_ancestor(
                root_fd,
                changed_path,
                budget,
            )?);
        }

        candidates.sort_by(|left, right| {
            component_count(left)
                .cmp(&component_count(right))
                .then_with(|| left.cmp(right))
        });
        let mut deduplicated = Vec::<PathBuf>::with_capacity(candidates.len());
        for candidate in candidates {
            if deduplicated
                .iter()
                .any(|ancestor| candidate.starts_with(ancestor))
            {
                continue;
            }
            deduplicated.push(candidate);
        }
        Ok(deduplicated)
    }

    fn nearest_cached_existing_ancestor(
        &self,
        root_fd: &OwnedFd,
        initial: &Path,
        budget: &mut ScanBudget,
    ) -> Result<PathBuf, ReconcileError> {
        let mut candidate = initial.to_path_buf();
        loop {
            budget.check()?;
            if candidate.as_os_str().is_empty() {
                return Err(ReconcileError::full(
                    "no existing cached ancestor remains below the scan root",
                ));
            }
            if self.nodes.contains_key(&candidate) {
                match open_relative_directory(root_fd, &candidate) {
                    Ok(directory) => {
                        drop(directory);
                        return Ok(candidate);
                    }
                    Err(OpenRelativeError::Unavailable) => {}
                    Err(OpenRelativeError::Io(error)) => {
                        return Err(ReconcileError::Io(error));
                    }
                }
            }
            candidate = candidate
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf();
        }
    }

    fn commit_replacements(
        &mut self,
        staged: Vec<(PathBuf, HashMap<PathBuf, CachedDirectory>)>,
        limits: ScanLimits,
    ) -> Result<DirectoryUsage, ReconcileError> {
        let mut removed_paths = HashSet::new();
        let mut replacement_paths = HashSet::new();
        let mut deltas = HashMap::<PathBuf, UsageDelta>::new();

        for (candidate, replacement) in &staged {
            let old_total = self
                .nodes
                .get(candidate)
                .ok_or_else(|| ReconcileError::full("a cached dirty subtree disappeared"))?
                .total;
            let new_total = replacement
                .get(candidate)
                .ok_or_else(|| ReconcileError::full("a replacement scan omitted its subtree root"))?
                .total;
            collect_subtree_paths(&self.nodes, candidate, &mut removed_paths)?;
            for path in replacement.keys() {
                if !path.starts_with(candidate) || !replacement_paths.insert(path.clone()) {
                    return Err(ReconcileError::full(
                        "replacement subtrees overlap or contain an unrelated path",
                    ));
                }
            }

            let delta = UsageDelta::between(old_total, new_total);
            for ancestor in candidate.ancestors().skip(1) {
                let ancestor = ancestor.to_path_buf();
                if !self.nodes.contains_key(&ancestor) {
                    return Err(ReconcileError::full("a cached ancestor is missing"));
                }
                validate_cached_directory(&self.nodes, &ancestor)?;
                deltas.entry(ancestor).or_default().add(delta)?;
            }
        }

        let final_node_count = self
            .nodes
            .len()
            .checked_sub(removed_paths.len())
            .and_then(|count| count.checked_add(replacement_paths.len()))
            .ok_or_else(|| ReconcileError::full("cached directory count is inconsistent"))?;
        let maximum_entry_nodes = limits.max_entries.checked_add(1).ok_or_else(|| {
            ReconcileError::Io(Error::new(
                ErrorKind::InvalidInput,
                "disk scan entry limit is too large",
            ))
        })?;
        if final_node_count > self.max_cached_directories {
            return Err(ReconcileError::full(
                "the incremental cache directory bound was exceeded",
            ));
        }
        if final_node_count > maximum_entry_nodes {
            return Err(ReconcileError::Io(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "disk usage cache would contain {final_node_count} directories, exceeding the {} entry bound",
                    limits.max_entries
                ),
            )));
        }

        let mut updated_ancestors = HashMap::with_capacity(deltas.len());
        for (path, delta) in deltas {
            let old = self
                .nodes
                .get(&path)
                .ok_or_else(|| ReconcileError::full("cached ancestor disappeared"))?
                .total;
            let updated = delta.apply(old)?;
            updated_ancestors.insert(path, updated);
        }
        let final_usage = updated_ancestors
            .get(Path::new(""))
            .copied()
            .unwrap_or_else(|| self.usage());
        if final_usage.entries > limits.max_entries as u64 {
            return Err(ReconcileError::Io(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "disk usage cache contains {} entries, exceeding the {} entry bound",
                    final_usage.entries, limits.max_entries
                ),
            )));
        }

        // All fallible validation finishes before this in-memory commit.
        for path in removed_paths {
            self.nodes.remove(&path);
        }
        for (_, replacement) in staged {
            self.nodes.extend(replacement);
        }
        for (path, total) in updated_ancestors {
            if let Some(node) = self.nodes.get_mut(&path) {
                node.total = total;
            }
        }
        debug_assert_eq!(self.nodes.len(), final_node_count);
        debug_assert_eq!(self.usage(), final_usage);
        Ok(final_usage)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct UsageDelta {
    logical_bytes: i128,
    physical_bytes: i128,
    entries: i128,
}

impl UsageDelta {
    fn between(old: DirectoryUsage, new: DirectoryUsage) -> Self {
        Self {
            logical_bytes: i128::from(new.logical_bytes) - i128::from(old.logical_bytes),
            physical_bytes: i128::from(new.physical_bytes) - i128::from(old.physical_bytes),
            entries: i128::from(new.entries) - i128::from(old.entries),
        }
    }

    fn add(&mut self, other: Self) -> Result<(), ReconcileError> {
        self.logical_bytes = self
            .logical_bytes
            .checked_add(other.logical_bytes)
            .ok_or_else(|| ReconcileError::full("logical usage delta overflow"))?;
        self.physical_bytes = self
            .physical_bytes
            .checked_add(other.physical_bytes)
            .ok_or_else(|| ReconcileError::full("physical usage delta overflow"))?;
        self.entries = self
            .entries
            .checked_add(other.entries)
            .ok_or_else(|| ReconcileError::full("entry usage delta overflow"))?;
        Ok(())
    }

    fn apply(self, usage: DirectoryUsage) -> Result<DirectoryUsage, ReconcileError> {
        Ok(DirectoryUsage {
            logical_bytes: apply_delta(usage.logical_bytes, self.logical_bytes, "logical")?,
            physical_bytes: apply_delta(usage.physical_bytes, self.physical_bytes, "physical")?,
            entries: apply_delta(usage.entries, self.entries, "entry")?,
        })
    }
}

fn apply_delta(value: u64, delta: i128, field: &str) -> Result<u64, ReconcileError> {
    let updated = i128::from(value)
        .checked_add(delta)
        .ok_or_else(|| ReconcileError::full(format!("cached {field} usage delta overflow")))?;
    u64::try_from(updated).map_err(|_| {
        ReconcileError::full(format!(
            "cached {field} usage would become negative or overflow"
        ))
    })
}

struct ScanBudget {
    started: Instant,
    limits: ScanLimits,
    entries: u64,
}

impl ScanBudget {
    fn new(limits: ScanLimits) -> Self {
        Self {
            started: Instant::now(),
            limits,
            entries: 0,
        }
    }

    fn check(&self) -> Result<(), Error> {
        if self.started.elapsed() >= self.limits.timeout {
            return Err(Error::new(
                ErrorKind::TimedOut,
                format!("disk scan timed out after {} entries", self.entries),
            ));
        }
        Ok(())
    }

    fn visit_entry(&mut self) -> Result<(), Error> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "disk scan entry count overflow"))?;
        if self.entries > self.limits.max_entries as u64 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("disk scan exceeded {} entries", self.limits.max_entries),
            ));
        }
        Ok(())
    }
}

fn scan_directory_tree(
    directory: &OwnedFd,
    directory_stat: &Stat,
    relative_path: &Path,
    depth: usize,
    budget: &mut ScanBudget,
    nodes: &mut HashMap<PathBuf, CachedDirectory>,
    max_cached_directories: usize,
) -> Result<DirectoryUsage, Error> {
    budget.check()?;
    let mut base = DirectoryUsage {
        physical_bytes: allocated_bytes(directory_stat)?,
        ..DirectoryUsage::default()
    };
    let mut descendant_usage = DirectoryUsage::default();
    let mut children = BTreeSet::new();
    let entries = Dir::read_from(directory).map_err(Error::from)?;
    for entry in entries {
        budget.check()?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if transient_entry_error(error) => continue,
            Err(error) => return Err(Error::from(error)),
        };
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        budget.visit_entry()?;
        base.entries = checked_add(base.entries, 1, "disk scan entry count")?;
        let stat = match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(error) if transient_entry_error(error) => continue,
            Err(error) => return Err(Error::from(error)),
        };
        let allocated = allocated_bytes(&stat)?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                if depth >= budget.limits.max_depth {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("disk scan exceeded depth {}", budget.limits.max_depth),
                    ));
                }
                let child = match openat(
                    directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(child) => child,
                    Err(error) if transient_entry_error(error) => {
                        base.physical_bytes =
                            checked_add(base.physical_bytes, allocated, "allocated disk usage")?;
                        continue;
                    }
                    Err(error) => return Err(Error::from(error)),
                };
                let opened_stat = fstat(&child).map_err(Error::from)?;
                if identity_from_stat(&opened_stat)? != identity_from_stat(&stat)? {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "directory changed identity while the disk scan opened it",
                    ));
                }
                let child_name = os_string(name);
                let child_path = relative_path.join(&child_name);
                let child_total = scan_directory_tree(
                    &child,
                    &stat,
                    &child_path,
                    depth + 1,
                    budget,
                    nodes,
                    max_cached_directories,
                )?;
                children.insert(child_name);
                add_usage(&mut descendant_usage, child_total)?;
            }
            FileType::RegularFile => {
                base.physical_bytes =
                    checked_add(base.physical_bytes, allocated, "allocated disk usage")?;
                let size = u64::try_from(stat.st_size).map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "file reported a negative size")
                })?;
                base.logical_bytes = checked_add(base.logical_bytes, size, "logical disk usage")?;
            }
            _ => {
                base.physical_bytes =
                    checked_add(base.physical_bytes, allocated, "allocated disk usage")?;
            }
        }
    }

    let mut total = base;
    add_usage(&mut total, descendant_usage)?;
    let previous = nodes.insert(
        relative_path.to_path_buf(),
        CachedDirectory {
            base,
            total,
            children,
        },
    );
    if previous.is_some() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "disk scan produced a duplicate cached directory path",
        ));
    }
    if nodes.len() > max_cached_directories {
        return Err(Error::new(
            ErrorKind::FileTooLarge,
            CACHE_DIRECTORY_LIMIT_MESSAGE,
        ));
    }
    Ok(total)
}

fn is_cache_directory_limit_error(error: &Error) -> bool {
    error.kind() == ErrorKind::FileTooLarge && error.to_string() == CACHE_DIRECTORY_LIMIT_MESSAGE
}

fn collect_subtree_paths(
    nodes: &HashMap<PathBuf, CachedDirectory>,
    root: &Path,
    collected: &mut HashSet<PathBuf>,
) -> Result<(), ReconcileError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if !collected.insert(path.clone()) {
            return Err(ReconcileError::full(
                "cached subtrees overlap or contain a cycle",
            ));
        }
        let node = nodes
            .get(&path)
            .ok_or_else(|| ReconcileError::full("a cached directory is missing"))?;
        validate_cached_directory(nodes, &path)?;
        for child in &node.children {
            if !is_single_normal_component(child) {
                return Err(ReconcileError::full(
                    "cached child contains an unsafe path component",
                ));
            }
            pending.push(path.join(child));
        }
    }
    Ok(())
}

fn validate_cached_directory(
    nodes: &HashMap<PathBuf, CachedDirectory>,
    path: &Path,
) -> Result<(), ReconcileError> {
    let node = nodes
        .get(path)
        .ok_or_else(|| ReconcileError::full("a cached directory is missing"))?;
    let mut calculated = node.base;
    for child in &node.children {
        if !is_single_normal_component(child) {
            return Err(ReconcileError::full(
                "a cached child contains an unsafe path component",
            ));
        }
        let child_total = nodes
            .get(&path.join(child))
            .ok_or_else(|| ReconcileError::full("a cached child is missing"))?
            .total;
        add_usage(&mut calculated, child_total).map_err(|_| {
            ReconcileError::full("cached directory aggregate arithmetic is invalid")
        })?;
    }
    if calculated != node.total {
        return Err(ReconcileError::full(
            "a cached directory aggregate is inconsistent",
        ));
    }
    Ok(())
}

fn validate_complete_tree(
    nodes: &HashMap<PathBuf, CachedDirectory>,
    limits: ScanLimits,
) -> Result<(), Error> {
    let root = nodes
        .get(Path::new(""))
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "disk usage cache has no root"))?;
    let maximum_nodes = limits.max_entries.checked_add(1).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "disk scan entry limit is too large",
        )
    })?;
    if nodes.len() > maximum_nodes || root.total.entries > limits.max_entries as u64 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "disk usage cache exceeds the configured entry bound",
        ));
    }
    Ok(())
}

fn open_root(path: &Path) -> Result<(OwnedFd, RootIdentity, Stat), Error> {
    let directory = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(Error::from)?;
    let stat = fstat(&directory).map_err(Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "disk scan root is not a directory",
        ));
    }
    let identity = identity_from_stat(&stat)?;
    Ok((directory, identity, stat))
}

enum OpenRelativeError {
    Unavailable,
    Io(Error),
}

fn open_relative_directory(
    root: &OwnedFd,
    relative_path: &Path,
) -> Result<OwnedFd, OpenRelativeError> {
    let mut directory = fcntl_dupfd_cloexec(root, 0)
        .map_err(Error::from)
        .map_err(OpenRelativeError::Io)?;
    for component in relative_path.components() {
        let Component::Normal(name) = component else {
            return Err(OpenRelativeError::Io(Error::new(
                ErrorKind::InvalidInput,
                "disk scan path is not a clean relative path",
            )));
        };
        directory = match openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(directory) => directory,
            Err(error) if unavailable_path_error(error) => {
                return Err(OpenRelativeError::Unavailable);
            }
            Err(error) => return Err(OpenRelativeError::Io(Error::from(error))),
        };
    }
    Ok(directory)
}

fn validate_changed_path(path: &Path) -> Result<(), ReconcileError> {
    if path.as_os_str().is_empty() {
        return Err(ReconcileError::full(
            "a dirty event names the scan root directly",
        ));
    }
    if path.components().all(|component| {
        matches!(component, Component::Normal(name) if is_single_normal_component(name))
    }) {
        return Ok(());
    }
    Err(ReconcileError::full(
        "a dirty path is not a clean root-relative path",
    ))
}

fn is_single_normal_component(name: &OsStr) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn unavailable_path_error(error: Errno) -> bool {
    matches!(
        error,
        Errno::NOENT | Errno::STALE | Errno::NOTDIR | Errno::LOOP
    )
}

fn transient_entry_error(error: Errno) -> bool {
    matches!(error, Errno::NOENT | Errno::STALE)
}

fn identity_from_stat(stat: &Stat) -> Result<RootIdentity, Error> {
    Ok(RootIdentity {
        device: stat_number_u64(stat.st_dev, "negative filesystem device id")?,
        inode: stat_number_u64(stat.st_ino, "negative filesystem inode")?,
    })
}

fn allocated_bytes(stat: &Stat) -> Result<u64, Error> {
    let blocks = stat_number_u64(
        stat.st_blocks,
        "file reported a negative allocated block count",
    )?;
    blocks
        .checked_mul(ALLOCATION_BLOCK_BYTES)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "allocated disk usage overflow"))
}

fn stat_number_u64<T>(value: T, error: &'static str) -> Result<u64, Error>
where
    T: TryInto<u64>,
{
    value
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, error))
}

fn checked_add(left: u64, right: u64, field: &str) -> Result<u64, Error> {
    left.checked_add(right)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, format!("{field} overflow")))
}

fn add_usage(target: &mut DirectoryUsage, source: DirectoryUsage) -> Result<(), Error> {
    target.logical_bytes = checked_add(
        target.logical_bytes,
        source.logical_bytes,
        "logical disk usage",
    )?;
    target.physical_bytes = checked_add(
        target.physical_bytes,
        source.physical_bytes,
        "allocated disk usage",
    )?;
    target.entries = checked_add(target.entries, source.entries, "disk scan entry count")?;
    Ok(())
}

fn component_count(path: &Path) -> usize {
    path.components().count()
}

fn os_string(name: &std::ffi::CStr) -> OsString {
    use std::os::unix::ffi::OsStrExt;

    OsStr::from_bytes(name.to_bytes()).to_os_string()
}

#[cfg(test)]
#[path = "usage_tree_tests.rs"]
mod tests;
