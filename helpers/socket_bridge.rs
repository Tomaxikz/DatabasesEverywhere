#![deny(warnings)]

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
    env, fs,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
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
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(500);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
// All bridges share one epoll thread, so connections no longer cost PIDs.
// The cap bounds file descriptors (two per connection) and buffer memory
// (two fixed buffers per established connection, about 32 MiB in total).
const MAX_ACTIVE_BRIDGE_CONNECTIONS: usize = 512;
const RESERVED_FILE_DESCRIPTORS: u64 = 32;
// Per-direction buffer. A full buffer stops reads from that direction's source,
// which leaves data in the kernel socket buffer and pushes back on the sender.
const PIPE_BUFFER_SIZE: usize = 32 * 1024;
// Bytes one direction may move per reactor turn before yielding to others.
const TURN_BUDGET: usize = 256 * 1024;
const EPOLL_BATCH: usize = 256;

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
    let mut listeners = Vec::with_capacity(bridges.len());
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
        listeners.push((listener, bridge.target));
    }
    let reactor = Reactor::new(listeners, connection_limit())
        .map_err(|error| format!("failed to start socket bridge event loop: {error}"))?;
    thread::Builder::new()
        .name("dbev-socket-bridge".to_string())
        .spawn(move || reactor.run())
        .map_err(|error| format!("failed to start socket bridge event loop: {error}"))?;
    Ok(sockets)
}

fn connection_limit() -> usize {
    let soft_limit = sys::open_file_limit().unwrap_or(1024);
    let by_descriptors = soft_limit.saturating_sub(RESERVED_FILE_DESCRIPTORS) / 2;
    usize::try_from(by_descriptors)
        .unwrap_or(usize::MAX)
        .clamp(1, MAX_ACTIVE_BRIDGE_CONNECTIONS)
}

const TAG_LISTENER: u64 = 0;
const TAG_CLIENT: u64 = 1;
const TAG_BACKEND: u64 = 2;
const STREAM_INTEREST: u32 = sys::EPOLLIN | sys::EPOLLOUT | sys::EPOLLRDHUP | sys::EPOLLET;
const LISTENER_INTEREST: u32 = sys::EPOLLIN | sys::EPOLLET;

fn token(index: usize, tag: u64) -> u64 {
    ((index as u64) << 2) | tag
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TimerKey {
    Listener(usize),
    Connection { slot: usize, epoch: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting before the next backend connection attempt.
    RetryWait,
    /// A non-blocking backend connect is in flight.
    Connecting,
    Established,
}

#[derive(Debug, Default, Clone, Copy)]
struct Readiness {
    readable: bool,
    writable: bool,
}

impl Readiness {
    fn observe(&mut self, events: u32) {
        if events & (sys::EPOLLIN | sys::EPOLLRDHUP | sys::EPOLLHUP | sys::EPOLLERR) != 0 {
            self.readable = true;
        }
        if events & (sys::EPOLLOUT | sys::EPOLLHUP | sys::EPOLLERR) != 0 {
            self.writable = true;
        }
    }
}

/// One direction of a proxied connection with a fixed, bounded buffer.
#[derive(Debug, Default)]
struct Pipe {
    buffer: Box<[u8]>,
    start: usize,
    end: usize,
    /// The source returned EOF.
    source_closed: bool,
    /// EOF was forwarded to the sink with a write shutdown.
    sink_closed: bool,
}

impl Pipe {
    fn allocate(&mut self) {
        if self.buffer.is_empty() {
            self.buffer = vec![0; PIPE_BUFFER_SIZE].into_boxed_slice();
        }
    }

    /// Ends this direction after an I/O error, like EOF, while the opposite
    /// direction keeps draining (for example a database error response).
    fn abort(&mut self, sink: &impl HalfClose) {
        self.source_closed = true;
        self.start = 0;
        self.end = 0;
        if !self.sink_closed {
            self.sink_closed = true;
            sink.shutdown_write();
        }
    }
}

trait HalfClose {
    fn shutdown_write(&self);
}

impl HalfClose for UnixStream {
    fn shutdown_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

impl HalfClose for TcpStream {
    fn shutdown_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

/// Moves bytes from `source` to `sink` until neither side can make progress.
/// Returns `true` when the turn budget ran out while progress was still possible.
fn transfer<R, W>(
    source: &R,
    source_readable: &mut bool,
    sink: &W,
    sink_writable: &mut bool,
    pipe: &mut Pipe,
) -> io::Result<bool>
where
    for<'a> &'a R: Read,
    for<'a> &'a W: Write,
    W: HalfClose,
{
    let mut moved = 0usize;
    loop {
        let mut progressed = false;
        while pipe.start < pipe.end && *sink_writable {
            let mut writer = sink;
            match writer.write(&pipe.buffer[pipe.start..pipe.end]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => {
                    pipe.start += written;
                    moved += written;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    *sink_writable = false;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        if pipe.start == pipe.end {
            pipe.start = 0;
            pipe.end = 0;
        }

        if !pipe.source_closed && *source_readable && pipe.end < pipe.buffer.len() {
            let mut reader = source;
            match reader.read(&mut pipe.buffer[pipe.end..]) {
                Ok(0) => {
                    pipe.source_closed = true;
                    progressed = true;
                }
                Ok(read) => {
                    pipe.end += read;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    *source_readable = false;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    progressed = true;
                }
                Err(error) => return Err(error),
            }
        }

        if pipe.source_closed && pipe.start == pipe.end && !pipe.sink_closed {
            pipe.sink_closed = true;
            sink.shutdown_write();
        }
        if !progressed {
            return Ok(false);
        }
        if moved >= TURN_BUDGET {
            return Ok(true);
        }
    }
}

#[derive(Debug)]
struct Connection {
    client: UnixStream,
    backend: Option<TcpStream>,
    target: SocketAddr,
    phase: Phase,
    connect_deadline: Instant,
    timer_epoch: u64,
    queued: bool,
    client_ready: Readiness,
    backend_ready: Readiness,
    upstream: Pipe,
    downstream: Pipe,
    /// First I/O error, reported when the connection closes.
    error: Option<io::Error>,
}

#[derive(Debug)]
struct ListenerEntry {
    socket: UnixListener,
    target: SocketAddr,
}

enum ConnectProgress {
    Pending,
    Connected,
    Failed(io::Error),
}

/// Single-threaded, edge-triggered epoll proxy for every bridge listener.
struct Reactor {
    epoll: sys::Epoll,
    listeners: Vec<ListenerEntry>,
    slots: Vec<Option<Connection>>,
    free_slots: Vec<usize>,
    // Slots closed during the current turn. They are reused only after the turn
    // so stale events from the same epoll batch cannot reach a new connection.
    released_slots: Vec<usize>,
    ready: VecDeque<usize>,
    timers: BinaryHeap<Reverse<(Instant, TimerKey)>>,
    next_epoch: u64,
    active: usize,
    max_connections: usize,
    rejection_reported: bool,
}

impl Reactor {
    fn new(listeners: Vec<(UnixListener, SocketAddr)>, max_connections: usize) -> io::Result<Self> {
        let epoll = sys::Epoll::new()?;
        let mut entries = Vec::with_capacity(listeners.len());
        for (index, (socket, target)) in listeners.into_iter().enumerate() {
            socket.set_nonblocking(true)?;
            epoll.add(
                socket.as_raw_fd(),
                token(index, TAG_LISTENER),
                LISTENER_INTEREST,
            )?;
            entries.push(ListenerEntry { socket, target });
        }
        Ok(Self {
            epoll,
            listeners: entries,
            slots: Vec::new(),
            free_slots: Vec::new(),
            released_slots: Vec::new(),
            ready: VecDeque::new(),
            timers: BinaryHeap::new(),
            next_epoch: 0,
            active: 0,
            max_connections: max_connections.max(1),
            rejection_reported: false,
        })
    }

    fn run(mut self) {
        let mut events = vec![sys::EpollEvent { events: 0, data: 0 }; EPOLL_BATCH];
        // Listeners are edge-triggered; drain anything queued before registration.
        for index in 0..self.listeners.len() {
            self.accept_ready(index);
        }
        loop {
            let timeout = if self.ready.is_empty() {
                self.next_timeout_ms()
            } else {
                0
            };
            let count = match self.epoll.wait(&mut events, timeout) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => 0,
                Err(error) => {
                    eprintln!("dbev socket bridge event wait failed: {error}");
                    thread::sleep(POLL_INTERVAL);
                    0
                }
            };
            for event in &events[..count] {
                let (data, flags) = (event.data, event.events);
                self.dispatch(data, flags);
            }
            self.fire_timers();
            self.drain_ready_queue();
            self.free_slots.append(&mut self.released_slots);
        }
    }

    fn next_timeout_ms(&self) -> i32 {
        let Some(Reverse((deadline, _))) = self.timers.peek() else {
            return -1;
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining.as_nanos().div_ceil(1_000_000);
        i32::try_from(millis).unwrap_or(i32::MAX)
    }

    fn dispatch(&mut self, data: u64, flags: u32) {
        let index = (data >> 2) as usize;
        match data & 0b11 {
            TAG_LISTENER => self.accept_ready(index),
            TAG_CLIENT => {
                let Some(Some(connection)) = self.slots.get_mut(index) else {
                    return;
                };
                connection.client_ready.observe(flags);
                // Cancel a pending backend connect when the client went away
                // without leaving a request behind.
                if connection.phase != Phase::Established
                    && flags & (sys::EPOLLHUP | sys::EPOLLERR) != 0
                    && !sys::has_buffered_input(&connection.client)
                {
                    self.close(index, None);
                    return;
                }
                self.drive(index);
            }
            TAG_BACKEND => {
                let Some(Some(connection)) = self.slots.get_mut(index) else {
                    return;
                };
                connection.backend_ready.observe(flags);
                self.drive(index);
            }
            _ => {}
        }
    }

    fn accept_ready(&mut self, index: usize) {
        loop {
            let Some(listener) = self.listeners.get(index) else {
                return;
            };
            let target = listener.target;
            match listener.socket.accept() {
                Ok((stream, _)) => self.admit(stream, target),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                    ) => {}
                Err(error) => {
                    // Edge-triggered listeners will not report the pending
                    // connection again, so retry accept on a timer.
                    eprintln!("dbev socket bridge accept failed: {error}");
                    self.timers.push(Reverse((
                        Instant::now() + POLL_INTERVAL,
                        TimerKey::Listener(index),
                    )));
                    return;
                }
            }
        }
    }

    fn admit(&mut self, client: UnixStream, target: SocketAddr) {
        if self.active >= self.max_connections {
            if !self.rejection_reported {
                self.rejection_reported = true;
                eprintln!(
                    "dbev socket bridge reached its {}-connection safety limit",
                    self.max_connections
                );
            }
            let _ = client.shutdown(Shutdown::Both);
            return;
        }
        if let Err(error) = client.set_nonblocking(true) {
            eprintln!("dbev socket bridge connection to {target} failed: {error}");
            return;
        }
        let slot = match self.free_slots.pop() {
            Some(slot) => slot,
            None => {
                self.slots.push(None);
                self.slots.len() - 1
            }
        };
        if let Err(error) =
            self.epoll
                .add(client.as_raw_fd(), token(slot, TAG_CLIENT), STREAM_INTEREST)
        {
            eprintln!("dbev socket bridge connection to {target} failed: {error}");
            self.free_slots.push(slot);
            return;
        }
        let now = Instant::now();
        self.slots[slot] = Some(Connection {
            client,
            backend: None,
            target,
            phase: Phase::RetryWait,
            connect_deadline: now + CONNECT_TIMEOUT,
            timer_epoch: 0,
            queued: false,
            client_ready: Readiness::default(),
            backend_ready: Readiness::default(),
            upstream: Pipe::default(),
            downstream: Pipe::default(),
            error: None,
        });
        self.active += 1;
        self.start_connect(slot, now);
    }

    fn connection(&mut self, slot: usize) -> Option<&mut Connection> {
        self.slots.get_mut(slot).and_then(Option::as_mut)
    }

    fn schedule(&mut self, slot: usize, deadline: Instant) {
        self.next_epoch += 1;
        let epoch = self.next_epoch;
        if let Some(connection) = self.slots.get_mut(slot).and_then(Option::as_mut) {
            connection.timer_epoch = epoch;
            self.timers
                .push(Reverse((deadline, TimerKey::Connection { slot, epoch })));
        }
    }

    fn start_connect(&mut self, slot: usize, now: Instant) {
        let Some(connection) = self.connection(slot) else {
            return;
        };
        let target = connection.target;
        let (backend, in_progress) = match sys::connect_nonblocking(target) {
            Ok(result) => result,
            Err(error) => return self.retry_or_fail(slot, error, now),
        };
        if let Err(error) =
            self.epoll
                .add(backend.as_raw_fd(), token(slot, TAG_BACKEND), STREAM_INTEREST)
        {
            return self.close(slot, Some(error));
        }
        let Some(connection) = self.connection(slot) else {
            return;
        };
        connection.backend = Some(backend);
        connection.backend_ready = Readiness::default();
        if in_progress {
            connection.phase = Phase::Connecting;
            self.schedule(slot, now + CONNECT_ATTEMPT_TIMEOUT);
        } else {
            self.establish(slot);
            self.drive(slot);
        }
    }

    fn retry_or_fail(&mut self, slot: usize, error: io::Error, now: Instant) {
        let Some(connection) = self.connection(slot) else {
            return;
        };
        connection.backend = None;
        connection.backend_ready = Readiness::default();
        if now < connection.connect_deadline {
            connection.phase = Phase::RetryWait;
            self.schedule(slot, now + POLL_INTERVAL);
        } else {
            self.close(slot, Some(error));
        }
    }

    fn establish(&mut self, slot: usize) {
        self.next_epoch += 1;
        let epoch = self.next_epoch;
        let Some(connection) = self.connection(slot) else {
            return;
        };
        // Invalidate the pending attempt timer.
        connection.timer_epoch = epoch;
        connection.phase = Phase::Established;
        connection.upstream.allocate();
        connection.downstream.allocate();
        // Edges observed before the backend connected were already consumed;
        // probe both sockets once and let EAGAIN clear the flags.
        connection.client_ready = Readiness {
            readable: true,
            writable: true,
        };
        connection.backend_ready = Readiness {
            readable: true,
            writable: true,
        };
    }

    fn connect_progress(connection: &Connection) -> ConnectProgress {
        let Some(backend) = connection.backend.as_ref() else {
            return ConnectProgress::Pending;
        };
        match backend.take_error() {
            Ok(Some(error)) | Err(error) => return ConnectProgress::Failed(error),
            Ok(None) => {}
        }
        match backend.peer_addr() {
            Ok(_) => ConnectProgress::Connected,
            Err(error) if error.kind() == io::ErrorKind::NotConnected => ConnectProgress::Pending,
            Err(error) => ConnectProgress::Failed(error),
        }
    }

    fn drive(&mut self, slot: usize) {
        let Some(connection) = self.connection(slot) else {
            return;
        };
        match connection.phase {
            Phase::RetryWait => return,
            Phase::Connecting => {
                if !connection.backend_ready.writable && !connection.backend_ready.readable {
                    return;
                }
                match Self::connect_progress(connection) {
                    ConnectProgress::Pending => {
                        connection.backend_ready = Readiness::default();
                        return;
                    }
                    ConnectProgress::Failed(error) => {
                        return self.retry_or_fail(slot, error, Instant::now());
                    }
                    ConnectProgress::Connected => self.establish(slot),
                }
            }
            Phase::Established => {}
        }
        self.pump(slot);
    }

    fn pump(&mut self, slot: usize) {
        let Some(connection) = self.slots.get_mut(slot).and_then(Option::as_mut) else {
            return;
        };
        if connection.phase != Phase::Established {
            return;
        }
        let Some(backend) = connection.backend.as_ref() else {
            return;
        };
        let more_up = transfer(
            &connection.client,
            &mut connection.client_ready.readable,
            backend,
            &mut connection.backend_ready.writable,
            &mut connection.upstream,
        )
        .unwrap_or_else(|error| {
            connection.upstream.abort(backend);
            connection.error.get_or_insert(error);
            false
        });
        let more_down = transfer(
            backend,
            &mut connection.backend_ready.readable,
            &connection.client,
            &mut connection.client_ready.writable,
            &mut connection.downstream,
        )
        .unwrap_or_else(|error| {
            connection.downstream.abort(&connection.client);
            connection.error.get_or_insert(error);
            false
        });
        if connection.upstream.sink_closed && connection.downstream.sink_closed {
            let error = connection.error.take();
            self.close(slot, error);
        } else if (more_up || more_down) && !connection.queued {
            connection.queued = true;
            self.ready.push_back(slot);
        }
    }

    fn drain_ready_queue(&mut self) {
        for _ in 0..self.ready.len() {
            let Some(slot) = self.ready.pop_front() else {
                return;
            };
            if let Some(connection) = self.connection(slot) {
                connection.queued = false;
                self.pump(slot);
            }
        }
    }

    fn fire_timers(&mut self) {
        let now = Instant::now();
        while let Some(Reverse((deadline, key))) = self.timers.peek().copied() {
            if deadline > now {
                return;
            }
            self.timers.pop();
            match key {
                TimerKey::Listener(index) => self.accept_ready(index),
                TimerKey::Connection { slot, epoch } => {
                    let Some(connection) = self.connection(slot) else {
                        continue;
                    };
                    if connection.timer_epoch != epoch {
                        continue;
                    }
                    match connection.phase {
                        Phase::RetryWait => self.start_connect(slot, now),
                        Phase::Connecting => self.retry_or_fail(
                            slot,
                            io::Error::new(io::ErrorKind::TimedOut, "connection timed out"),
                            now,
                        ),
                        Phase::Established => {}
                    }
                }
            }
        }
    }

    fn close(&mut self, slot: usize, error: Option<io::Error>) {
        let Some(connection) = self.slots.get_mut(slot).and_then(Option::take) else {
            return;
        };
        if let Some(error) = error {
            eprintln!(
                "dbev socket bridge connection to {} failed: {error}",
                connection.target
            );
        }
        // Dropping the only descriptors removes them from the epoll set and
        // closes the backend, which cancels any in-flight database work.
        drop(connection);
        self.active -= 1;
        self.rejection_reported = false;
        self.released_slots.push(slot);
    }
}

mod sys {
    use std::{
        io,
        net::{SocketAddr, TcpStream},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
            unix::net::UnixStream,
        },
    };

    // Linux generic values, identical on x86-64, AArch64 and RISC-V.
    const EPOLL_CLOEXEC: i32 = 0o2_000_000;
    const EPOLL_CTL_ADD: i32 = 1;
    pub const EPOLLIN: u32 = 0x001;
    pub const EPOLLOUT: u32 = 0x004;
    pub const EPOLLERR: u32 = 0x008;
    pub const EPOLLHUP: u32 = 0x010;
    pub const EPOLLRDHUP: u32 = 0x2000;
    pub const EPOLLET: u32 = 1 << 31;
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    const SOCK_STREAM: i32 = 1;
    const SOCK_NONBLOCK: i32 = 0o4_000;
    const SOCK_CLOEXEC: i32 = 0o2_000_000;
    const MSG_DONTWAIT: i32 = 0x40;
    const MSG_PEEK: i32 = 0x02;
    const EINPROGRESS: i32 = 115;
    const EINTR: i32 = 4;
    const RLIMIT_NOFILE: i32 = 7;

    // The kernel ABI packs epoll_event on x86-64 only.
    #[cfg_attr(target_arch = "x86_64", repr(C, packed))]
    #[cfg_attr(not(target_arch = "x86_64"), repr(C))]
    #[derive(Clone, Copy)]
    pub struct EpollEvent {
        pub events: u32,
        pub data: u64,
    }

    #[repr(C)]
    struct RLimit {
        current: u64,
        maximum: u64,
    }

    #[repr(C, align(4))]
    struct SockAddr([u8; 28]);

    unsafe extern "C" {
        fn epoll_create1(flags: i32) -> i32;
        fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32;
        fn epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32;
        fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
        fn connect(fd: i32, address: *const SockAddr, length: u32) -> i32;
        fn recv(fd: i32, buffer: *mut u8, length: usize, flags: i32) -> isize;
        fn getrlimit(resource: i32, limit: *mut RLimit) -> i32;
    }

    pub struct Epoll(OwnedFd);

    impl Epoll {
        pub fn new() -> io::Result<Self> {
            let fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
        }

        pub fn add(&self, fd: RawFd, data: u64, events: u32) -> io::Result<()> {
            let mut event = EpollEvent { events, data };
            if unsafe { epoll_ctl(self.0.as_raw_fd(), EPOLL_CTL_ADD, fd, &mut event) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn wait(&self, events: &mut [EpollEvent], timeout_ms: i32) -> io::Result<usize> {
            let capacity = i32::try_from(events.len()).unwrap_or(i32::MAX);
            let count = unsafe {
                epoll_wait(
                    self.0.as_raw_fd(),
                    events.as_mut_ptr(),
                    capacity,
                    timeout_ms,
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(count as usize)
        }
    }

    /// Starts a non-blocking TCP connect. Returns whether it is still in progress.
    pub fn connect_nonblocking(target: SocketAddr) -> io::Result<(TcpStream, bool)> {
        let mut address = SockAddr([0; 28]);
        let (family, length) = match target {
            SocketAddr::V4(v4) => {
                address.0[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
                address.0[2..4].copy_from_slice(&v4.port().to_be_bytes());
                address.0[4..8].copy_from_slice(&v4.ip().octets());
                (AF_INET, 16)
            }
            SocketAddr::V6(v6) => {
                address.0[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
                address.0[2..4].copy_from_slice(&v6.port().to_be_bytes());
                address.0[4..8].copy_from_slice(&v6.flowinfo().to_be_bytes());
                address.0[8..24].copy_from_slice(&v6.ip().octets());
                address.0[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
                (AF_INET6, 28)
            }
        };
        let fd = unsafe {
            socket(
                i32::from(family),
                SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = unsafe { TcpStream::from_raw_fd(fd) };
        stream.set_nodelay(true)?;
        if unsafe { connect(fd, &address, length) } == 0 {
            return Ok((stream, false));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            // An interrupted non-blocking connect continues asynchronously.
            Some(EINPROGRESS | EINTR) => Ok((stream, true)),
            _ => Err(error),
        }
    }

    /// Whether a client that hung up still left unread request bytes behind.
    pub fn has_buffered_input(stream: &UnixStream) -> bool {
        let mut byte = 0u8;
        let read = unsafe { recv(stream.as_raw_fd(), &mut byte, 1, MSG_PEEK | MSG_DONTWAIT) };
        read > 0
    }

    pub fn open_file_limit() -> Option<u64> {
        let mut limit = RLimit {
            current: 0,
            maximum: 0,
        };
        (unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) } == 0).then_some(limit.current)
    }
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

// Run with: rustc --edition=2024 --test helpers/socket_bridge.rs -o /tmp/bridge-tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::TcpListener,
        sync::atomic::AtomicUsize,
        time::Duration,
    };

    static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);
    const TEST_TIMEOUT: Duration = Duration::from_secs(20);

    fn socket_path() -> PathBuf {
        let index = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "dbev-bridge-test-{}-{index}.sock",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    fn start_bridge(target: SocketAddr, max_connections: usize) -> PathBuf {
        let path = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let reactor = Reactor::new(vec![(listener, target)], max_connections).unwrap();
        thread::spawn(move || reactor.run());
        path
    }

    fn client(path: &Path) -> UnixStream {
        let stream = UnixStream::connect(path).unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream
    }

    fn unused_port() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
    }

    fn pattern(length: usize, seed: u8) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// Reads the whole request (up to EOF), then answers and closes.
    fn spawn_request_response_backend(listener: TcpListener) -> thread::JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(b"response:").unwrap();
            stream.write_all(&request).unwrap();
            request
        })
    }

    #[test]
    fn forwards_half_close_in_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let path = start_bridge(listener.local_addr().unwrap(), 8);
        let backend = spawn_request_response_backend(listener);

        let mut stream = client(&path);
        stream.write_all(b"query").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();

        assert_eq!(backend.join().unwrap(), b"query");
        assert_eq!(response, b"response:query");
    }

    #[test]
    fn streams_large_bidirectional_payloads_through_bounded_buffers() {
        const LENGTH: usize = 8 * 1024 * 1024;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let path = start_bridge(listener.local_addr().unwrap(), 8);
        // Echo backend: copies everything back until EOF, then half-closes.
        let backend = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = stream.try_clone().unwrap();
            let mut writer = stream;
            io::copy(&mut reader, &mut writer).unwrap();
            writer.shutdown(Shutdown::Write).unwrap();
        });

        let stream = client(&path);
        let mut writer = stream.try_clone().unwrap();
        let payload = pattern(LENGTH, 7);
        let expected = payload.clone();
        let upload = thread::spawn(move || {
            writer.write_all(&payload).unwrap();
            writer.shutdown(Shutdown::Write).unwrap();
        });
        // A slow reader forces the bridge buffers to fill and apply backpressure.
        thread::sleep(Duration::from_millis(300));
        let mut echoed = Vec::with_capacity(LENGTH);
        (&stream).read_to_end(&mut echoed).unwrap();

        upload.join().unwrap();
        backend.join().unwrap();
        assert_eq!(echoed.len(), expected.len());
        assert!(echoed == expected, "echoed bytes differ");
    }

    #[test]
    fn client_disconnect_closes_backend_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let path = start_bridge(listener.local_addr().unwrap(), 8);
        let backend = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
            let chunk = [0x5a; 16 * 1024];
            let started = Instant::now();
            loop {
                if let Err(error) = stream.write_all(&chunk) {
                    return (error.kind(), started.elapsed());
                }
            }
        });

        let mut stream = client(&path);
        let mut first = [0u8; 1024];
        stream.read_exact(&mut first).unwrap();
        drop(stream);

        let (kind, elapsed) = backend.join().unwrap();
        assert!(
            matches!(
                kind,
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ),
            "unexpected backend error {kind:?}"
        );
        assert!(elapsed < TEST_TIMEOUT);
    }

    #[test]
    fn retries_until_backend_starts_listening() {
        let target = unused_port();
        let path = start_bridge(target, 8);
        let mut stream = client(&path);
        stream.write_all(b"early").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();

        thread::sleep(Duration::from_millis(700));
        let backend = spawn_request_response_backend(TcpListener::bind(target).unwrap());
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();

        assert_eq!(backend.join().unwrap(), b"early");
        assert_eq!(response, b"response:early");
    }

    #[test]
    fn rejects_connections_beyond_limit_and_recovers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let path = start_bridge(listener.local_addr().unwrap(), 1);
        let first = client(&path);
        let (held, _) = listener.accept().unwrap();

        let mut rejected = client(&path);
        let mut buffer = Vec::new();
        assert_eq!(rejected.read_to_end(&mut buffer).unwrap(), 0);

        drop(first);
        drop(held);
        thread::sleep(Duration::from_millis(200));
        let backend = spawn_request_response_backend(listener);
        let mut stream = client(&path);
        stream.write_all(b"again").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response:again");
        backend.join().unwrap();
    }

    #[test]
    fn client_hangup_cancels_pending_backend_connect() {
        let target = unused_port();
        let path = start_bridge(target, 1);
        // Holds the only slot while the backend is down, then disappears.
        drop(client(&path));
        thread::sleep(Duration::from_millis(300));

        let mut stream = client(&path);
        stream.write_all(b"second").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        thread::sleep(Duration::from_millis(300));
        let backend = spawn_request_response_backend(TcpListener::bind(target).unwrap());
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();

        assert_eq!(backend.join().unwrap(), b"second");
        assert_eq!(response, b"response:second");
    }

    #[test]
    fn many_concurrent_connections_share_one_thread() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let path = start_bridge(listener.local_addr().unwrap(), 64);
        let backend = thread::spawn(move || {
            let mut handlers = Vec::new();
            for _ in 0..48 {
                let (mut stream, _) = listener.accept().unwrap();
                handlers.push(thread::spawn(move || {
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).unwrap();
                    stream.write_all(&request).unwrap();
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        });
        let clients = (0..48u8)
            .map(|seed| {
                let path = path.clone();
                thread::spawn(move || {
                    let mut stream = client(&path);
                    let payload = pattern(64 * 1024 + usize::from(seed), seed);
                    stream.write_all(&payload).unwrap();
                    stream.shutdown(Shutdown::Write).unwrap();
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response).unwrap();
                    assert!(response == payload);
                })
            })
            .collect::<Vec<_>>();
        for client in clients {
            client.join().unwrap();
        }
        backend.join().unwrap();
    }

    #[test]
    fn connection_limit_respects_descriptor_budget() {
        let limit = connection_limit();
        assert!((1..=MAX_ACTIVE_BRIDGE_CONNECTIONS).contains(&limit));
    }
}
