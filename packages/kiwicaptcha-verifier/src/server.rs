//! The std-only HTTP surface: the request reader with its size caps, the
//! bounded worker pool and the accept loops.
//!
//! Concurrency contract: a fixed pool of workers serves accepted
//! connections; a stalled client holds one worker only until its
//! per-connection timeout fires, and a full pool answers overflow with an
//! immediate 503 instead of piling up threads. The pool bounds the
//! thread count by construction, so a slowloris-style opener cannot
//! exhaust the process.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use crate::config::{MAX_BODY_BYTES, MAX_HEAD_BYTES};
use crate::state::SidecarState;

/// The Prometheus exposition content type (text format 0.0.4), the same
/// value the bundle's exporter serves.
pub const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The parsed listen address.
#[derive(Debug, Clone)]
pub enum ListenAddr {
    Http(SocketAddr),
    Unix(PathBuf),
}

/// Parse a listen string: `http://127.0.0.1:7371` or
/// `unix:///path/to/socket`. HTTP bindings outside the loopback range are
/// refused, since the sidecar is a localhost service by contract.
pub fn parse_listen(raw: &str) -> Result<ListenAddr, String> {
    if let Some(path) = raw.strip_prefix("unix://") {
        if path.is_empty() {
            return Err("unix:// needs a socket path".to_string());
        }
        return Ok(ListenAddr::Unix(PathBuf::from(path)));
    }
    let host_port = raw.strip_prefix("http://").ok_or_else(|| {
        format!("unrecognized listen address: {raw} (want http://IP:PORT or unix:///PATH)")
    })?;
    let addr: SocketAddr = host_port
        .parse()
        .map_err(|e| format!("cannot parse listen address {raw}: {e}"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "refusing to bind {addr}: the sidecar binds loopback only (127.0.0.1 or ::1)"
        ));
    }
    Ok(ListenAddr::Http(addr))
}

/// Constant-time byte equality (a missing credential fails closed; a
/// length mismatch still walks the presented bytes so the comparison
/// time carries no signal).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// A parsed HTTP request (method, path, the Authorization bearer and the
/// body).
pub(crate) struct Request {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

impl Request {
    pub(crate) fn bearer(&self) -> Option<&str> {
        self.authorization
            .as_deref()
            .and_then(|v| v.strip_prefix("Bearer "))
    }
}

/// Why the reader gave up on a connection: a timeout is answered with
/// 408 so the client sees its stall, anything else with 400.
#[derive(Debug)]
pub(crate) enum ReadFailure {
    Timeout,
    Malformed(String),
}

/// The response the handlers return.
pub(crate) struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
    pub extra_headers: Vec<(String, String)>,
}

impl Response {
    pub fn raw(status: u16, content_type: &'static str, body: String) -> Self {
        Self {
            status,
            content_type,
            body,
            extra_headers: Vec::new(),
        }
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self::raw(status, "text/plain; charset=utf-8", body.to_string())
    }

    pub fn json(status: u16, body: String) -> Self {
        Self::raw(status, "application/json", body)
    }

    pub fn unauthorized() -> Self {
        Self::text(401, "unauthorized\n")
    }

    pub fn with_header(mut self, name: &str, value: String) -> Self {
        self.extra_headers.push((name.to_string(), value));
        self
    }

    fn status_line(&self) -> &'static str {
        match self.status {
            200 => "200 OK",
            400 => "400 Bad Request",
            401 => "401 Unauthorized",
            403 => "403 Forbidden",
            404 => "404 Not Found",
            405 => "405 Method Not Allowed",
            408 => "408 Request Timeout",
            413 => "413 Payload Too Large",
            429 => "429 Too Many Requests",
            503 => "503 Service Unavailable",
            _ => "500 Internal Server Error",
        }
    }
}

/// Read one HTTP/1.1 request from the stream (request line, headers,
/// Content-Length body). The reader never allocates beyond the two
/// bounded caps, and every blocking read carries the stream's timeout.
pub(crate) fn read_request<R: Read>(stream: &mut R) -> Result<Request, ReadFailure> {
    let read_once = |stream: &mut R, chunk: &mut [u8]| -> Result<Vec<u8>, ReadFailure> {
        match stream.read(chunk) {
            Ok(n) if n > 0 => Ok(chunk[..n].to_vec()),
            Ok(_) => Err(ReadFailure::Malformed("connection closed".to_string())),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Err(ReadFailure::Timeout)
            }
            Err(e) => Err(ReadFailure::Malformed(e.to_string())),
        }
    };
    let mut head: Vec<u8> = Vec::with_capacity(1024);
    loop {
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HEAD_BYTES {
            return Err(ReadFailure::Malformed("header block too large".to_string()));
        }
        let chunk = read_once(stream, &mut [0u8; 4096])?;
        head.extend_from_slice(&chunk);
    }
    let split = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ReadFailure::Malformed("no header terminator".to_string()))?;
    let head_text = String::from_utf8_lossy(&head[..split]).to_string();
    let mut lines = head_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| ReadFailure::Malformed("empty request".to_string()))?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let path = target.split('?').next().unwrap_or("").to_string();
    let mut content_length = 0usize;
    let mut authorization = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value
                .parse()
                .map_err(|_| ReadFailure::Malformed("bad content-length".to_string()))?;
        } else if name == "authorization" {
            authorization = Some(value.to_string());
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err(ReadFailure::Malformed("body too large".to_string()));
    }
    let mut body = head[split + 4..].to_vec();
    if body.len() > content_length {
        body.truncate(content_length);
    }
    while body.len() < content_length {
        let chunk = read_once(stream, &mut [0u8; 4096])?;
        let take = chunk.len().min(content_length - body.len());
        body.extend_from_slice(&chunk[..take]);
    }
    Ok(Request {
        method,
        path,
        authorization,
        body,
    })
}

/// Serve one connection: read, handle, answer, close (one request per
/// connection; a local sidecar call pays nothing for keep-alive). A
/// timed-out read answers 408 so the stalled client observes its stall.
/// Returns true when the connection ended on the read timeout.
pub(crate) fn serve_connection<S: Read + Write>(stream: &mut S, state: &SidecarState) -> bool {
    let response = match read_request(stream) {
        Ok(req) => state.handle(&req),
        Err(ReadFailure::Timeout) => {
            state.pool.timeouts.fetch_add(1, Ordering::Relaxed);
            Response::text(408, "request timeout\n")
        }
        Err(ReadFailure::Malformed(reason)) => match reason.as_str() {
            "body too large" => Response::text(413, "body too large\n"),
            "header block too large" => Response::text(400, "header block too large\n"),
            _ => Response::text(400, "bad request\n"),
        },
    };
    let mut head = format!(
        "HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n",
        response.status_line(),
        response.content_type,
        response.body.len()
    );
    for (name, value) in &response.extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(response.body.as_bytes());
    let _ = stream.flush();
    response.status == 408
}

/// The worker-pool job: one accepted stream with its transport tag.
enum Job {
    Tcp(TcpStream),
    Unix(UnixStream),
}

/// Counters for the pool's health (exposed through `/metrics`).
#[derive(Default)]
pub struct PoolMetrics {
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub timeouts: AtomicU64,
}

impl PoolMetrics {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.accepted.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
            self.timeouts.load(Ordering::Relaxed),
        )
    }
}

/// The bounded connection pool: `workers` threads over a bounded queue.
/// Overflow is refused with an immediate 503, so the memory and thread
/// footprint stays constant no matter how many sockets arrive.
pub struct ServerOptions {
    pub workers: usize,
    pub timeout: Duration,
}

impl Default for ServerOptions {
    fn default() -> Self {
        ServerOptions {
            workers: crate::config::DEFAULT_WORKERS,
            timeout: Duration::from_millis(crate::config::DEFAULT_TIMEOUT_MS),
        }
    }
}

fn worker_loop(receiver: Arc<Mutex<mpsc::Receiver<Job>>>, state: Arc<SidecarState>) {
    loop {
        let job = {
            let guard = receiver.lock().expect("job queue lock");
            match guard.recv() {
                Ok(job) => job,
                Err(_) => return,
            }
        };
        let mut job = job;
        match &mut job {
            Job::Tcp(stream) => {
                serve_connection(stream, &state);
            }
            Job::Unix(stream) => {
                serve_connection(stream, &state);
            }
        }
    }
}

fn prepare_tcp(stream: TcpStream, timeout: Duration) -> TcpStream {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    stream
}

fn spawn_pool(state: &Arc<SidecarState>, options: &ServerOptions) -> mpsc::SyncSender<Job> {
    let (sender, receiver) = mpsc::sync_channel::<Job>(options.workers.saturating_mul(4));
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..options.workers.max(1) {
        let receiver = Arc::clone(&receiver);
        let state = Arc::clone(state);
        std::thread::spawn(move || worker_loop(receiver, state));
    }
    sender
}

fn reject_overflow(mut stream: TcpStream) {
    let body = "service busy\n";
    let head = format!(
        "HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nretry-after: 1\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

/// The TCP accept loop over the bounded worker pool. Returns only on a
/// listener error.
pub fn serve_http(listener: TcpListener, state: Arc<SidecarState>) -> std::io::Result<()> {
    serve_http_with(listener, state, ServerOptions::default())
}

/// The TCP accept loop with explicit pool options (the binary's entry).
pub fn serve_http_with(
    listener: TcpListener,
    state: Arc<SidecarState>,
    options: ServerOptions,
) -> std::io::Result<()> {
    let sender = spawn_pool(&state, &options);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        state.pool.accepted.fetch_add(1, Ordering::Relaxed);
        let stream = prepare_tcp(stream, options.timeout);
        match sender.try_send(Job::Tcp(stream)) {
            Ok(()) => {}
            Err(err) => {
                state.pool.rejected.fetch_add(1, Ordering::Relaxed);
                // The bounded queue is full: the stream comes back with
                // the error, so answer busy and close instead of
                // queueing another stalled connection.
                if let mpsc::TrySendError::Full(Job::Tcp(back)) = err {
                    reject_overflow(back);
                }
            }
        }
    }
    Ok(())
}

/// The Unix-socket accept loop over the same pool (the socket file's
/// permissions are the deployment's boundary).
pub fn serve_unix(path: &Path, state: Arc<SidecarState>) -> std::io::Result<()> {
    serve_unix_with(path, state, ServerOptions::default())
}

/// The Unix-socket accept loop with explicit pool options.
pub fn serve_unix_with(
    path: &Path,
    state: Arc<SidecarState>,
    options: ServerOptions,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    let sender = spawn_pool(&state, &options);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        state.pool.accepted.fetch_add(1, Ordering::Relaxed);
        let _ = stream.set_read_timeout(Some(options.timeout));
        let _ = stream.set_write_timeout(Some(options.timeout));
        match sender.try_send(Job::Unix(stream)) {
            Ok(()) => {}
            Err(_) => {
                state.pool.rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    Ok(())
}

/// Bind and serve on the parsed address with the default pool; returns
/// only on error.
pub fn serve(listen: &ListenAddr, state: Arc<SidecarState>) -> std::io::Result<()> {
    serve_with(listen, state, ServerOptions::default())
}

/// Bind and serve on the parsed address with explicit pool options.
pub fn serve_with(
    listen: &ListenAddr,
    state: Arc<SidecarState>,
    options: ServerOptions,
) -> std::io::Result<()> {
    match listen {
        ListenAddr::Http(addr) => {
            let listener = TcpListener::bind(*addr)?;
            serve_http_with(listener, state, options)
        }
        ListenAddr::Unix(path) => serve_unix_with(path, state, options),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_loopback_binds() {
        assert!(parse_listen("http://0.0.0.0:7371").is_err());
        assert!(parse_listen("http://192.0.2.10:7371").is_err());
        assert!(parse_listen("http://127.0.0.1:7371").is_ok());
        assert!(parse_listen("unix:///tmp/kiwi.sock").is_ok());
        assert!(parse_listen("gopher://x").is_err());
    }

    #[test]
    fn constant_time_compare_matches_only_equal_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
