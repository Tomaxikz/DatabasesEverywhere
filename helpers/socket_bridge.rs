#![deny(warnings)]

use std::{
    env,
    fs,
    io,
    net::{Shutdown, SocketAddr, TcpStream},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const SUPERVISOR_COMMAND: &str = "__socket-bridge-supervisor";
const HEALTHCHECK_COMMAND: &str = "__socket-bridge-healthcheck";
const SOCKET_ROOT: &str = "/run/dbev";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

static TERMINATE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
struct Bridge {
    socket_path: PathBuf,
    target: SocketAddr,
}

#[derive(Debug)]
struct Invocation {
    bridges: Vec<Bridge>,
    command: Vec<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dbev socket bridge: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some(SUPERVISOR_COMMAND) => supervise(parse_invocation(arguments)?),
        Some(HEALTHCHECK_COMMAND) => healthcheck(arguments),
        _ => Err("unknown or missing internal command".to_string()),
    }
}

fn healthcheck(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let target = arguments
        .next()
        .ok_or_else(|| "healthcheck is missing its target".to_string())?
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid healthcheck target: {error}"))?;
    if arguments.next().is_some() || !valid_target(target) {
        return Err("healthcheck requires one non-zero loopback target".to_string());
    }
    TcpStream::connect_timeout(&target, Duration::from_secs(5))
        .map(|_| ())
        .map_err(|error| format!("healthcheck connection failed: {error}"))
}

fn parse_invocation(arguments: impl IntoIterator<Item = String>) -> Result<Invocation, String> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let separator = arguments
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| "supervisor invocation is missing '--'".to_string())?;
    let options = &arguments[..separator];
    let command = arguments[separator + 1..].to_vec();
    if command.is_empty() {
        return Err("supervisor invocation is missing the database command".to_string());
    }
    if options.is_empty() || options.len() % 4 != 0 {
        return Err(
            "bridges must be provided as '--socket PATH --tcp ADDRESS' pairs".to_string(),
        );
    }

    let mut bridges = Vec::with_capacity(options.len() / 4);
    for chunk in options.chunks_exact(4) {
        if chunk[0] != "--socket" || chunk[2] != "--tcp" {
            return Err(
                "bridges must be provided as '--socket PATH --tcp ADDRESS' pairs".to_string(),
            );
        }
        let socket_path = PathBuf::from(&chunk[1]);
        if !valid_socket_path(&socket_path) {
            return Err(format!(
                "socket path must be a direct child of {SOCKET_ROOT}"
            ));
        }
        let target = chunk[3]
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid TCP target {}: {error}", chunk[3]))?;
        if !valid_target(target) {
            return Err("TCP target must be a non-zero loopback address".to_string());
        }
        bridges.push(Bridge {
            socket_path,
            target,
        });
    }

    Ok(Invocation { bridges, command })
}

fn valid_socket_path(path: &Path) -> bool {
    path.is_absolute()
        && path.starts_with(SOCKET_ROOT)
        && path.parent() == Some(Path::new(SOCKET_ROOT))
}

fn valid_target(target: SocketAddr) -> bool {
    target.ip().is_loopback() && target.port() != 0
}

fn supervise(invocation: Invocation) -> Result<(), String> {
    install_signal_handlers()?;
    let mut child = Command::new(&invocation.command[0])
        .args(&invocation.command[1..])
        .spawn()
        .map_err(|error| {
            format!(
                "failed to start database command {}: {error}",
                invocation.command[0]
            )
        })?;

    let sockets = match bind_bridges(&invocation.bridges) {
        Ok(sockets) => sockets,
        Err(error) => {
            terminate_child(&mut child);
            return Err(error);
        }
    };
    let _cleanup = SocketCleanup(sockets);

    loop {
        if TERMINATE.load(Ordering::SeqCst) {
            terminate_child(&mut child);
            return Ok(());
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => return Err(format!("database process exited with {status}")),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => return Err(format!("failed to wait for database process: {error}")),
        }
    }
}

fn bind_bridges(bridges: &[Bridge]) -> Result<Vec<PathBuf>, String> {
    let mut sockets = Vec::with_capacity(bridges.len());
    for bridge in bridges {
        remove_stale_socket(&bridge.socket_path)?;
        let listener = UnixListener::bind(&bridge.socket_path).map_err(|error| {
            format!(
                "failed to bind socket {}: {error}",
                bridge.socket_path.display()
            )
        })?;
        fs::set_permissions(&bridge.socket_path, fs::Permissions::from_mode(0o660)).map_err(
            |error| {
                format!(
                    "failed to set socket permissions on {}: {error}",
                    bridge.socket_path.display()
                )
            },
        )?;
        sockets.push(bridge.socket_path.clone());
        let target = bridge.target;
        thread::Builder::new()
            .name("dbev-socket-accept".to_string())
            .spawn(move || accept_connections(listener, target))
            .map_err(|error| format!("failed to start socket accept loop: {error}"))?;
    }
    Ok(sockets)
}

fn accept_connections(listener: UnixListener, target: SocketAddr) {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(error) = thread::Builder::new()
                    .name("dbev-socket-proxy".to_string())
                    .spawn(move || {
                        if let Err(error) = proxy_connection(stream, target) {
                            eprintln!("dbev socket bridge connection to {target} failed: {error}");
                        }
                    })
                {
                    eprintln!("dbev socket bridge failed to start proxy thread: {error}");
                }
            }
            Err(error) => {
                eprintln!("dbev socket bridge accept failed: {error}");
                thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

fn proxy_connection(client: UnixStream, target: SocketAddr) -> io::Result<()> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let backend = loop {
        match TcpStream::connect_timeout(&target, Duration::from_millis(500)) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    };
    backend.set_nodelay(true)?;

    let mut client_reader = client.try_clone()?;
    let mut backend_writer = backend.try_clone()?;
    let upstream = thread::spawn(move || {
        let result = io::copy(&mut client_reader, &mut backend_writer);
        let _ = backend_writer.shutdown(Shutdown::Write);
        result
    });

    let mut backend_reader = backend;
    let mut client_writer = client;
    let downstream = io::copy(&mut backend_reader, &mut client_writer);
    let _ = client_writer.shutdown(Shutdown::Write);
    let upstream = upstream
        .join()
        .map_err(|_| io::Error::other("upstream proxy thread panicked"))?;
    upstream?;
    downstream?;
    Ok(())
}

fn remove_stale_socket(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)
            .map_err(|error| format!("failed to remove stale socket {}: {error}", path.display())),
        Ok(_) => Err(format!(
            "refusing to replace non-socket path {}",
            path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

fn install_signal_handlers() -> Result<(), String> {
    unsafe extern "C" {
        fn signal(signal: i32, handler: extern "C" fn(i32)) -> usize;
    }
    extern "C" fn handle_signal(_signal: i32) {
        TERMINATE.store(true, Ordering::SeqCst);
    }
    const SIGNAL_ERROR: usize = usize::MAX;
    for signal_number in [2, 15] {
        let previous = unsafe { signal(signal_number, handle_signal) };
        if previous == SIGNAL_ERROR {
            return Err(format!(
                "failed to install signal handler for signal {signal_number}"
            ));
        }
    }
    Ok(())
}

fn terminate_child(child: &mut Child) {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = unsafe { kill(pid, 15) };
    }
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

struct SocketCleanup(Vec<PathBuf>);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}
