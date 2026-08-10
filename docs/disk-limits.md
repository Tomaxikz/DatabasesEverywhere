# Disk limits

DBEV separates **hard filesystem enforcement** from **soft scanner
enforcement**. Hard limits reject an allocation at the filesystem boundary.
The scanner measures usage, predicts near-term growth, and intentionally stops
an instance before it can consume the node, but it cannot provide the same
guarantee as a kernel quota.

## Mode selection

```yaml
disk:
  mode: auto
  project_id_base: 200000
  fuse_quota_binary: embedded
  fuse_quota_binary_sha256: ""
  fuse_quota_rescan_interval_seconds: 150
  soft_scanner:
    scan_interval_seconds: 15
    use_inotify: true
    full_scan_interval_seconds: 90
    inotify_debounce_milliseconds: 500
    max_dirty_paths_per_instance: 512
    max_concurrent_scans: 2
    max_entries_per_scan: 1000000
    scan_timeout_seconds: 30
    max_consecutive_scan_failures: 3
    safety_reserve_mib: 64
    recovery_percent: 85
    shutdown_grace_seconds: 30
```

The soft scanner uses the same hybrid model as Wings: one recursive inotify
watcher coalesces changed paths, bounded partial scans replace only affected
subtrees in the cached usage tree, and periodic full scans reconcile anything
notifications cannot observe. DBEV additionally treats queue overflow, watcher
errors, cache/root replacement, and dirty-path saturation as mandatory full
reconciliation. A watcher failure never disables enforcement; that instance
falls back to periodic full scans. Qdrant always receives a full scan at
`scan_interval_seconds` because mmap-backed writes may not emit inotify events.

The configured target interval for authoritative full scans is the greater of
`full_scan_interval_seconds` and `scan_interval_seconds`, and both are bounded
to one hour. Completion can be later when the active scanner fleet generates
more work than `max_concurrent_scans` can process. Size concurrency for the
number and size of instances, and monitor scanner completion latency; this is
one reason soft enforcement is intentionally not described as a hard quota.
This preserves older configurations that used a longer base interval.
`max_dirty_paths_per_instance` bounds memory during event storms; exceeding it
deliberately collapses the hints into one full scan. Incremental usage trees are
additionally capped at 4,096 directories per instance and 32,768 directories
process-wide. A target that exceeds either cache cap drops its tree and safely
uses the original bounded-memory streaming full scan. Inotify is an
accelerator, not a quota boundary: only native project quotas or FuseQuota
provide hard write-time enforcement.

`disk.mode` accepts:

| Value | Behaviour |
| --- | --- |
| `auto` | Prefer a supported native quota. Otherwise use FuseQuota, except that Qdrant uses the soft scanner. |
| `project_quota` | Require native filesystem quota support. Startup fails closed when the selected volumes filesystem is not ready. |
| `fuse_quota` | Use FuseQuota for compatible databases. Qdrant still uses the soft scanner because Qdrant does not consider FUSE safe for persistent vector storage. |
| `soft_scanner` | Use scanner enforcement for every database. The legacy spelling `none` is accepted as an alias, but limits are still actively monitored. |

The effective method is reported per instance. `disk_enforced: true` means a
hard write-time limit. Scanner-enforced instances deliberately report
`disk_enforced: false` and `disk_enforcement_method: soft_scanner` so a panel
does not mistake prediction and shutdown for a kernel quota.

Major-version image upgrades use a rollback-safe directory cutover. DBEV
currently rejects that operation during preflight for native project-quota
instances because project IDs, qgroups, and mounted datasets require a
backend-specific transactional transfer. Use export, create a fresh target,
then import for those instances; the rejection happens before the source is
stopped or modified.

For soft-limited instances the existing resource-report disk object also
includes optional `scanner_logical_bytes`, `scanner_physical_bytes`, current
and peak `scanner_growth_bytes_per_second`,
`scanner_predicted_seconds_to_limit`, stop/recovery thresholds,
`scanner_restart_blocked`, and sample age. Hard-limited instances omit these
scanner fields unless a compatibility safety monitor is active.

Start by identifying the filesystem that actually backs the volume root:

```bash
findmnt -T /var/lib/dbev/volumes -o TARGET,SOURCE,FSTYPE,OPTIONS
sudo dbev --setup
```

Run `--setup` again after changing a mount or its quota options. DBEV validates
the detected facility before starting the daemon.

## ext4 project quotas

DBEV supports Linux project quotas on ext4 when all of the following are true:

- the ext4 filesystem has the `project` feature;
- it is mounted with `prjquota` (or `pquota`);
- `quotaon`, `setquota`, and `chattr` are installed;
- project quota accounting is active.

Inspect the exact device first:

```bash
volume_path=/var/lib/dbev/volumes
device="$(findmnt -n -o SOURCE -T "$volume_path")"
mountpoint="$(findmnt -n -o TARGET -T "$volume_path")"
printf 'device=%s mountpoint=%s\n' "$device" "$mountpoint"
sudo tune2fs -l "$device" | grep '^Filesystem features:'
findmnt -n -o OPTIONS -T "$volume_path" | tr ',' '\n' | grep -E '^(prjquota|pquota)$'
sudo quotaon -P -p "$mountpoint"
```

If the `project` feature is absent, enable it only during a planned maintenance
window with a verified backup. Follow the `tune2fs(8)` instructions shipped by
your distribution; the usual offline operation is `tune2fs -O project -Q
prjquota <device>` followed by a forced `e2fsck`. Never run an offline
filesystem repair against a mounted root filesystem.

Add `prjquota` to the correct `/etc/fstab` entry. For example:

```fstab
UUID=<filesystem-uuid> /var/lib/dbev ext4 defaults,prjquota 0 2
```

For a root filesystem, update its existing `/` entry instead and reboot. Do
not create a second conflicting root entry. After the reboot:

```bash
findmnt -T /var/lib/dbev/volumes -o TARGET,SOURCE,FSTYPE,OPTIONS
sudo quotaon -P /var/lib/dbev
sudo dbev --setup
```

If the volumes live on `/`, use `/` in the `quotaon` command.

References: [`ext4(5)` project/prjquota](https://man7.org/linux/man-pages/man5/ext4.5.html),
[`tune2fs(8)`](https://man7.org/linux/man-pages/man8/tune2fs.8.html).

## XFS project quotas

The volumes path must be on XFS mounted with `prjquota` or `pquota`. Install
`xfsprogs`, add the option to the existing `/etc/fstab` entry, and reboot (the
initial mount must enable quota accounting):

```fstab
UUID=<filesystem-uuid> /var/lib/dbev xfs defaults,prjquota 0 2
```

Verify it before running setup:

```bash
findmnt -T /var/lib/dbev/volumes -o TARGET,SOURCE,FSTYPE,OPTIONS
sudo xfs_quota -x -c state /var/lib/dbev
sudo dbev --setup
```

DBEV allocates deterministic project IDs, maintains its entries in
`/etc/projects` and `/etc/projid`, and applies a hard project limit to each
instance directory. Coordinate with any other program that edits those files.

Reference: [Linux XFS mount and quota options](https://docs.kernel.org/admin-guide/xfs.html).

## F2FS project quotas

F2FS exposes project accounting through the `prjquota` mount option. Ensure
the host kernel and `f2fs-tools` support project quotas, add `prjquota` to the
correct `/etc/fstab` entry, then reboot and verify:

```bash
findmnt -T /var/lib/dbev/volumes -o TARGET,SOURCE,FSTYPE,OPTIONS
sudo quotaon -P -p "$(findmnt -n -o TARGET -T /var/lib/dbev/volumes)"
sudo dbev --setup
```

Reference: [Linux F2FS mount options](https://docs.kernel.org/filesystems/f2fs.html).

## Btrfs qgroups

Install `btrfs-progs` and ensure the volume root is inside the intended Btrfs
filesystem. DBEV enables qgroups when necessary and creates each new instance
data root as a subvolume:

```bash
mountpoint="$(findmnt -n -o TARGET -T /var/lib/dbev/volumes)"
sudo btrfs quota enable "$mountpoint"
sudo btrfs qgroup show "$mountpoint"
sudo dbev --setup
```

A non-empty ordinary directory cannot become a Btrfs subvolume in place.
Export or back up existing instances before moving them to a Btrfs-backed
volume, then recreate/import them. If `btrfs qgroup show` reports inconsistent
accounting, repair/rescan it before relying on the limits.

Reference: [Btrfs qgroup documentation](https://btrfs.readthedocs.io/en/latest/btrfs-qgroup.html).

## ZFS refquotas

Install the OpenZFS utilities and place `paths.volumes` beneath a mounted ZFS
filesystem dataset. DBEV creates one child dataset per new instance and sets a
hard `refquota`:

```bash
zfs list -o name,mountpoint,used,available,refquota
findmnt -T /var/lib/dbev/volumes -o TARGET,SOURCE,FSTYPE,OPTIONS
sudo dbev --setup
```

As with Btrfs, the first conversion requires an empty instance mountpoint.
Back up and recreate/import existing ordinary directories rather than trying
to place a dataset over live data.

Reference: [OpenZFS quotas and reservations](https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Datasets/Quotas%20and%20Reservations.html).

## FuseQuota fallback

FuseQuota works over filesystems without a supported native quota facility.
It is a hard user-space limit, but it adds filesystem overhead and compatibility
risk. The host needs `/dev/fuse`, permission to create FUSE mounts, and
`user_allow_other` in `/etc/fuse.conf`:

```bash
test -c /dev/fuse
grep -Eq '^[[:space:]]*user_allow_other([[:space:]]|$)' /etc/fuse.conf
sudo dbev --setup
```

The bundled helper is hash-verified before execution. An external helper must
be configured with its expected SHA-256. Qdrant is never mounted through this
driver; it uses native storage plus the scanner when no native quota is active.
Legacy Qdrant instances that predate this rule are migrated from FUSE to raw
scanner-managed storage on startup. If native project quota is selected, DBEV
defers that legacy migration before touching the container because adopting a
non-empty database into every native backend is not transactionally portable.
Temporarily select `soft_scanner` to perform the safe FUSE-to-raw migration, or
use a backup/create/import migration.

## Predictive soft scanner

The scanner performs bounded, symlink-safe walks of each instance data root.
It records both apparent file length and allocated blocks, tracks recent and
peak growth, estimates time to the configured limit, and reserves space for
writes that can occur during detection and database shutdown.

When the safe threshold is crossed, DBEV records an intentional disk-limit
stop, requests a graceful database shutdown, and sends `SIGKILL` only if the
container is still running after `shutdown_grace_seconds` (30 seconds by
default). Automatic restart remains blocked until usage falls below
`recovery_percent` or the configured limit is increased. Scan concurrency,
entry count, and runtime are bounded node-wide/per instance.

This remains soft enforcement. A process can allocate between scans, mmap
writes are not guaranteed to generate useful filesystem notifications, and
open-but-deleted files are not visible in a directory walk. Use native quotas
for hostile multi-tenant workloads whenever possible. For Qdrant on a host
without native quotas, the scanner is deliberately preferred over exposing
Qdrant data to a FUSE filesystem it considers unsafe.
