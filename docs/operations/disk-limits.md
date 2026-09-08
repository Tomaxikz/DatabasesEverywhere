# Disk limits

Hard quotas reject writes at the filesystem boundary. Soft guards measure
usage and stop or fence a database near its limit; they can overshoot between
samples. Panels must distinguish these guarantees.

## Mode selection

Set `disk.mode`; all tuning fields and defaults are in the
[example config](../../config/example.yml).

| Mode | Behavior |
| --- | --- |
| `auto` | Prefer native quotas; otherwise FuseQuota, or the soft scanner for Qdrant |
| `project_quota` | Require supported native quotas; fail closed if the filesystem is not ready |
| `fuse_quota` | FuseQuota for compatible engines; Qdrant still uses the scanner |
| `soft_scanner` | Scanner enforcement; the alias `none` does **not** disable limits |

Reports set `disk_enforced: true` only for hard write-time limits.
Soft enforcement reports `false` and its enforcement method.

Identify the filesystem backing the volume root, then validate it:

```bash
findmnt -T /var/lib/dbev/volumes -o TARGET,SOURCE,FSTYPE,OPTIONS
sudo dbev --setup
```

Rerun setup after changing mounts or quota options. Reserve the project-ID
range exclusively for DBEV: up to one million IDs starting at
`disk.project_id_base` (default 200000), bounded by the 32-bit ID space.
Coordinate with other quota managers.

## FuseQuota memory

Each FUSE-mounted engine has a helper process. New helpers use at most two
I/O workers instead of libfuse's default ten; each worker retains a receive
buffer, so this bounds per-mount overhead without disabling quota checks or
filesystem caching. Very busy mounts trade some peak I/O parallelism for the
smaller footprint. It is not a hard process-memory limit.

Healthy helpers survive daemon restarts to keep database mounts usable. Their
worker settings change only when the mount is safely recreated, not merely
when DBEV restarts. Do not kill helpers or force-unmount active databases to
reclaim memory. Native project quotas avoid these userspace helpers entirely,
but changing enforcement needs a planned storage migration.

`systemctl status` reports memory for the whole service cgroup, including
helpers, charged file cache and kernel memory. Its peak is not DBEV's own RSS.

## Shared-tenant boundaries

| Tenant / filesystem | Enforcement |
| --- | --- |
| New PostgreSQL, MySQL, MariaDB tenants on project-quota-enabled XFS/ext4/F2FS | Independent hard project quota |
| MongoDB, ClickHouse, or legacy PostgreSQL in `pg_default` | Engine-catalog soft guard |
| Shared tenants on FuseQuota, Btrfs, ZFS, or other filesystems | Engine-catalog soft guard, even if the pool has a hard aggregate quota |

PostgreSQL uses a managed tenant tablespace. MySQL/MariaDB use the encoded
schema directory with file-per-table enabled; gateway policy rejects database
recreation and storage clauses that escape it. PostgreSQL tenants cannot
create explicit temporary tables or use global/default tablespaces.

Hard tenant limits cover persistent tables, indexes, and relations—not
engine-global WAL, redo/undo, journals, or server temporary files. The pool
root covers overhead and soft/unattached/recovery reservations without
double-counting durable child quotas. It also reserves 5% of total tenant
disk reservations, rounded up and capped at 8 GiB per pool, for engine-global
growth. Node admission charges this reserve too. PostgreSQL pools reserve
2 GiB of base overhead for WAL/checkpoint headroom.

Hard usage comes from kernel quota counters. Limits are restored before
routes reopen; the catalog sampler does not stop hard-quota tenants. A full
quota returns the engine's normal quota error while reads and deletion remain
possible. Disk shrinking uses a fenced physical check. Logical imports drain
sessions, verify usage after restore, and roll back oversized data before
reopening the route.

Adopting an existing soft pool into project quotas stops the engine first.
Unsafe or ambiguous layouts—including symlinks, special files, and foreign
project IDs—leave it stopped and quarantined. Released IDs are not reused.
Use tenant export/import into a new pool when safe adoption is impossible.

Shared ClickHouse denies whole-table `DROP`/`DETACH`, `FREEZE`,
partition move/fetch, and table-settings changes that could evade catalog
accounting. Administrator restore/delete still performs cleanup; detached
partition bytes count toward soft usage.

Choose dedicated placement when you need an independent CPU/memory boundary
or hard disk enforcement unavailable for your shared engine/filesystem.

## Image upgrades

Major-version upgrades require a rollback-safe directory cutover. Native
project-quota instances currently reject this during preflight, before
stopping or changing the source: project IDs, qgroups, and mounted datasets
need backend-specific transfer support. Export, create a fresh target, and
import instead. See [instance operations](../api/instances.md).

## ext4 project quotas

DBEV supports Linux project quotas on ext4 when all of the following are true:

- the ext4 filesystem has the `project` feature;
- it is mounted with `prjquota` (or `pquota`);
- `quotaon` and `setquota` are installed;
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
the host kernel and `f2fs-tools` support project quotas and that the filesystem
was formatted with `project_quota` plus its required `extra_attr` feature (and
the quota feature when using hidden quota inodes). Add `prjquota` to the correct
`/etc/fstab` entry, then reboot and verify:

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

FuseQuota provides a hard user-space limit on other filesystems, with extra
filesystem overhead and compatibility constraints. The host needs
`/dev/fuse`, permission to create FUSE mounts, and `user_allow_other`
in `/etc/fuse.conf`:

```bash
test -c /dev/fuse
grep -Eq '^[[:space:]]*user_allow_other([[:space:]]|$)' /etc/fuse.conf
sudo dbev --setup
```

The bundled helper is hash-verified. External helpers require an expected
SHA-256 and a trusted, root-owned executable path; the API cannot change this
setting. See [helper maintenance](../../helpers/README.md).

Qdrant never uses FUSE. Legacy FUSE-backed Qdrant data is migrated to raw
scanner-managed storage on startup. Selecting native quota mode defers this
migration before touching the container; use `soft_scanner` for the
FUSE-to-raw migration, or backup/create/import.

## Predictive soft scanner

Bounded, symlink-safe scans measure apparent and allocated bytes, recent
growth, and time to the limit. A reserve allows for writes during detection
and shutdown. Near the safe threshold, DBEV records an intentional disk stop
and requests graceful shutdown, then kills the still-running container after
the configured grace period. Restart is blocked until usage falls below the
recovery threshold or the limit increases.

Inotify accelerates partial rescans; periodic full scans reconcile changes.
Overflow, watcher errors, root replacement, and saturated caches force full
reconciliation. Watcher failure falls back to scanning, not disabled
enforcement. Qdrant gets full scans at the base interval because mmap writes
may not generate notifications.

Scan concurrency, work, runtime, and caches are bounded. Full-scan targets
use the greater of the base and full-scan intervals; a busy scanner fleet can
finish later. Monitor sample age rather than assuming the interval is a
deadline.

Resource reports expose nullable scanner sizes, growth, predicted time to
limit, stop/recovery thresholds, and restart-blocked state. Hard-limited
instances normally omit these fields.

Soft scans cannot guarantee write-time limits: writes can happen between
samples, mmap notifications are incomplete, and open-but-deleted files are
invisible to directory walks. Prefer native quotas for hostile multi-tenant
workloads.
