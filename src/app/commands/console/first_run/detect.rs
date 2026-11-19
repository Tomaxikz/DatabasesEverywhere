//! What the host offers: which container engines are present, and which
//! rootless Podman users exist.
//!
//! With the `podman-docker` package `docker` is a shim for Podman, so a
//! `docker` binary on PATH does not mean Docker. The decision is a pure
//! function over observed facts; [`installed`] only gathers them.

use std::{
    ffi::OsStr,
    io::Read,
    path::{Path, PathBuf},
};

use super::generate::ContainerRuntime;

/// A shim script is a few lines; anything bigger is a real program.
const SCRIPT_HEAD_BYTES: u64 = 4096;
const DOCKER_SOCKETS: [&str; 2] = ["/var/run/docker.sock", "/run/docker.sock"];
const ROOTFUL_PODMAN_SOCKET: &str = "/run/podman/podman.sock";
const USER_RUNTIME_ROOT: &str = "/run/user";

/// The `docker` found first on PATH.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct DockerBinary {
    /// The symlink target as written, then the fully resolved path.
    pub link_targets: Vec<PathBuf>,
    /// The start of the file when it is a small `#!` script.
    pub script_head: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct HostFacts {
    pub docker: Option<DockerBinary>,
    pub podman_binary: bool,
    /// A real Docker socket; one that links to Podman's does not count.
    pub docker_socket: bool,
    /// The rootful socket or any user's.
    pub podman_socket: bool,
}

impl DockerBinary {
    pub(super) fn is_podman_shim(&self) -> bool {
        let names_podman = |name: Option<&OsStr>| {
            name.and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with("podman"))
        };
        self.link_targets
            .iter()
            .any(|target| names_podman(target.file_name()))
            || self.script_head.as_deref().is_some_and(execs_podman)
    }
}

/// Whether a `#!` script hands over to podman (`exec /usr/bin/podman "$@"`).
fn execs_podman(script: &str) -> bool {
    if !script.starts_with("#!") {
        return false;
    }
    script
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .any(|line| {
            let mut words = line.split_whitespace().skip_while(|word| *word != "exec");
            words.next().is_some()
                && words.any(|word| {
                    Path::new(word.trim_matches(['"', '\'']))
                        .file_name()
                        .and_then(OsStr::to_str)
                        .is_some_and(|name| name.starts_with("podman"))
                })
        })
}

/// The usable engines, the one to preselect first.
pub(super) fn decide(facts: &HostFacts) -> Vec<ContainerRuntime> {
    let podman_present = facts.podman_binary || facts.podman_socket;
    match &facts.docker {
        // The shim stands for Podman however the sockets look.
        Some(docker) if docker.is_podman_shim() => vec![ContainerRuntime::Podman],
        // `docker` without a Docker daemon next to Podman is a stale client.
        Some(_) if !facts.docker_socket && podman_present => {
            vec![ContainerRuntime::Podman, ContainerRuntime::Docker]
        }
        Some(_) if podman_present => vec![ContainerRuntime::Docker, ContainerRuntime::Podman],
        Some(_) => vec![ContainerRuntime::Docker],
        None if podman_present => vec![ContainerRuntime::Podman],
        None => Vec::new(),
    }
}

/// The usable engines, and whether `docker` on PATH is really Podman.
pub(super) fn installed() -> (Vec<ContainerRuntime>, bool) {
    let facts = gather();
    let shim = facts
        .docker
        .as_ref()
        .is_some_and(DockerBinary::is_podman_shim);
    (decide(&facts), shim)
}

fn gather() -> HostFacts {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let on_path = |name: &str| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    };
    HostFacts {
        docker: on_path("docker").map(|binary| docker_binary(&binary)),
        podman_binary: on_path("podman").is_some(),
        docker_socket: DOCKER_SOCKETS.iter().any(|socket| {
            // podman-docker links /run/docker.sock to Podman's socket.
            std::fs::canonicalize(socket)
                .is_ok_and(|real| !real.to_string_lossy().contains("podman"))
        }),
        podman_socket: is_socket(Path::new(ROOTFUL_PODMAN_SOCKET))
            || !user_podman_sockets(Path::new(USER_RUNTIME_ROOT)).is_empty(),
    }
}

fn docker_binary(binary: &Path) -> DockerBinary {
    let mut link_targets = Vec::new();
    if let Ok(target) = std::fs::read_link(binary) {
        link_targets.push(target);
    }
    if let Ok(real) = std::fs::canonicalize(binary) {
        link_targets.push(real);
    }
    DockerBinary {
        link_targets,
        script_head: script_head(binary),
    }
}

fn script_head(binary: &Path) -> Option<String> {
    use std::os::unix::fs::OpenOptionsExt;

    // PATH may hold entries another user controls. Opening without blocking
    // and checking the opened file itself keeps a FIFO or a swapped entry
    // from stalling or misleading a wizard that runs as root.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(binary)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > SCRIPT_HEAD_BYTES {
        return None;
    }
    let mut head = Vec::new();
    file.take(SCRIPT_HEAD_BYTES).read_to_end(&mut head).ok()?;
    let head = String::from_utf8_lossy(&head).into_owned();
    head.starts_with("#!").then_some(head)
}

/// True for a Unix socket at `path` itself; a link or a regular file is not
/// evidence of an engine.
fn is_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;

    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
}

/// Uids with a Unix socket at `<root>/<uid>/podman/podman.sock`. This is a
/// hint for the wizard; setup and the daemon verify the engine on connect.
pub(super) fn user_podman_sockets(root: &Path) -> Vec<u32> {
    let mut uids: Vec<u32> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|uid| *uid != 0 && is_socket(&root.join(format!("{uid}/podman/podman.sock"))))
        .collect();
    uids.sort_unstable();
    uids
}

pub(super) fn detected_user_sockets() -> Vec<u32> {
    user_podman_sockets(Path::new(USER_RUNTIME_ROOT))
}

/// The user who ran `sudo dbev --cli`, never root.
pub(super) fn sudo_uid() -> Option<u32> {
    parse_uid(&std::env::var("SUDO_UID").ok()?)
}

pub(super) fn parse_uid(text: &str) -> Option<u32> {
    text.trim().parse::<u32>().ok().filter(|uid| *uid != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shim_link(target: &str) -> DockerBinary {
        DockerBinary {
            link_targets: vec![PathBuf::from(target), PathBuf::from("/usr/bin/podman")],
            script_head: None,
        }
    }

    fn script(text: &str) -> DockerBinary {
        DockerBinary {
            link_targets: vec![PathBuf::from("/usr/bin/docker")],
            script_head: Some(text.to_string()),
        }
    }

    fn real_docker() -> DockerBinary {
        DockerBinary {
            link_targets: vec![PathBuf::from("/usr/bin/docker")],
            script_head: None,
        }
    }

    fn facts(docker: Option<DockerBinary>) -> HostFacts {
        HostFacts {
            docker,
            ..HostFacts::default()
        }
    }

    use ContainerRuntime::{Docker, Podman};

    #[test]
    fn a_symlink_to_podman_is_a_shim() {
        assert!(shim_link("podman").is_podman_shim());
        assert!(shim_link("/usr/bin/podman").is_podman_shim());
        assert!(shim_link("/usr/bin/podman-remote").is_podman_shim());
        assert!(!real_docker().is_podman_shim());
    }

    #[test]
    fn a_script_that_execs_podman_is_a_shim() {
        assert!(script("#!/bin/sh\nexec /usr/bin/podman \"$@\"\n").is_podman_shim());
        assert!(script("#!/usr/bin/env bash\n# docker shim\nexec podman \"$@\"").is_podman_shim());
        assert!(script("#!/bin/sh\n  exec -a docker /usr/bin/podman \"$@\"").is_podman_shim());
        assert!(!script("#!/bin/sh\nexec /usr/bin/dockerd-real \"$@\"").is_podman_shim());
        assert!(
            !script("#!/bin/sh\n# exec podman is mentioned only here\necho hi").is_podman_shim()
        );
        // Not a script: an ELF header never counts, whatever follows it.
        assert!(!script("\u{7f}ELF exec podman").is_podman_shim());
    }

    #[test]
    fn the_shim_selects_podman_even_with_a_docker_socket() {
        let mut shim = facts(Some(shim_link("podman")));
        shim.docker_socket = true;
        assert_eq!(decide(&shim), [Podman]);
        shim.podman_binary = true;
        assert_eq!(decide(&shim), [Podman]);
    }

    #[test]
    fn real_docker_stays_the_default_when_its_socket_exists() {
        let mut host = facts(Some(real_docker()));
        host.docker_socket = true;
        assert_eq!(decide(&host), [Docker]);
        host.podman_binary = true;
        assert_eq!(decide(&host), [Docker, Podman]);
    }

    #[test]
    fn docker_without_a_socket_gives_way_to_podman() {
        let mut host = facts(Some(real_docker()));
        assert_eq!(decide(&host), [Docker], "nothing else to offer");
        host.podman_binary = true;
        assert_eq!(decide(&host), [Podman, Docker]);
        host.podman_binary = false;
        host.podman_socket = true;
        assert_eq!(decide(&host), [Podman, Docker]);
    }

    #[test]
    fn podman_alone_or_nothing() {
        assert!(decide(&facts(None)).is_empty());
        let mut host = facts(None);
        host.podman_binary = true;
        assert_eq!(decide(&host), [Podman]);
        let mut host = facts(None);
        host.podman_socket = true;
        assert_eq!(decide(&host), [Podman]);
    }

    #[test]
    fn user_sockets_are_found_by_uid() {
        let root = tempfile::tempdir().unwrap();
        let mut listeners = Vec::new();
        for uid in ["1000", "1001", "1002", "0", "abc"] {
            let directory = root.path().join(uid).join("podman");
            std::fs::create_dir_all(&directory).unwrap();
            let socket = directory.join("podman.sock");
            match uid {
                "1001" => {}
                // A regular file is not a socket.
                "1002" => std::fs::write(socket, "").unwrap(),
                _ => listeners.push(std::os::unix::net::UnixListener::bind(socket).unwrap()),
            }
        }
        assert_eq!(user_podman_sockets(root.path()), [1000]);
        assert_eq!(
            user_podman_sockets(&root.path().join("missing")),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn script_heads_are_read_only_for_small_scripts() {
        let directory = tempfile::tempdir().unwrap();
        let small = directory.path().join("small");
        std::fs::write(&small, "#!/bin/sh\nexec podman \"$@\"\n").unwrap();
        assert!(docker_binary(&small).is_podman_shim());
        let fifo = directory.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        // Would block forever on a plain open; must return at once instead.
        assert_eq!(docker_binary(&fifo).script_head, None);
        let big = directory.path().join("big");
        std::fs::write(&big, format!("#!/bin/sh\n{}", "#".repeat(5000))).unwrap();
        assert_eq!(docker_binary(&big).script_head, None);
        let link = directory.path().join("docker");
        let podman = directory.path().join("podman");
        std::fs::write(&podman, "").unwrap();
        std::os::unix::fs::symlink(&podman, &link).unwrap();
        assert!(docker_binary(&link).is_podman_shim());
    }

    #[test]
    fn uids_exclude_root_and_junk() {
        assert_eq!(parse_uid("1000"), Some(1000));
        assert_eq!(parse_uid(" 42\n"), Some(42));
        for text in ["0", "", "-1", "root", "1000x"] {
            assert_eq!(parse_uid(text), None, "{text}");
        }
    }
}
