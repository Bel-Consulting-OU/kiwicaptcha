//! A minimal std-only HTTP/1.1 client for the solver CLI.
//!
//! The CLI needs exactly one operation: POST a JSON document to a plain
//! http:// endpoint and read a bounded response body. The workspace has no
//! HTTP client dependency anywhere (no reqwest, no ureq), and pulling one in
//! would be the crate's heaviest dependency by far, so this module performs
//! the operation with std TCP plus a hand-written HTTP/1.1 writer and a
//! reader that understands both framing styles a real deployment answers
//! with: an explicit Content-Length or chunked transfer coding.
//!
//! Deliberate limitations, documented here and in the CLI help:
//! - https:// is refused with [`HttpError::HttpsUnsupported`]: there is no
//!   TLS stack in std. Pipe the endpoint through a local plaintext proxy or
//!   an HTTP CONNECT tunnel when the deployment is https-only.
//! - No redirects, no keep-alive (every request carries Connection: close),
//!   no compression (Accept is JSON only).
//! - The response body is capped at [`MAX_RESPONSE_BYTES`] so a hostile or
//!   broken endpoint cannot make the client allocate without bound.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// The hard cap on a response body (1 MiB). A challenge document is a few
/// hundred bytes and a siteverify response smaller still, so anything past
/// this bound is a broken or hostile endpoint, never a legitimate answer.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Per-socket timeouts: generous enough for a slow origin, bounded enough
/// that a wedged endpoint fails the CLI instead of hanging it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The response of one POST: the status code and the decoded body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why a request failed. Every variant maps to the CLI's usage/transport
/// exit code, never to a solver refusal.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("https endpoints are unsupported by the std-only client: pipe the endpoint through a local plaintext proxy or a CONNECT tunnel")]
    HttpsUnsupported,
    #[error("invalid endpoint URL: {0}")]
    InvalidUrl(&'static str),
    #[error("transport error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed HTTP response: {0}")]
    Protocol(&'static str),
    #[error("the response body exceeds the {0}-byte client cap")]
    TooLarge(usize),
}

/// POST `body` (a JSON document) to `url` with the extra request headers.
///
/// The client writes Host, User-Agent, Accept, Content-Type,
/// Content-Length and Connection itself; an extra header may not override
/// those transport-owned names, and no header name or value may carry a
/// control character (header injection stays impossible by construction).
pub fn post_json(
    url: &str,
    body: &str,
    extra_headers: &[(String, String)],
) -> Result<HttpResponse, HttpError> {
    let (host, port, path) = parse_http_url(url)?;
    // Resolve first so the connect timeout applies to the dial itself,
    // not just to reads on an established stream.
    let address = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(HttpError::Io)?
        .next();
    let address = match address {
        Some(addr) => addr,
        None => {
            return Err(HttpError::InvalidUrl(
                "the endpoint host does not resolve to a connectable address",
            ))
        }
    };
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;

    let host_header = if port == 80 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: kiwicaptcha-solver/{}\r\n\
         Accept: application/json\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        env!("CARGO_PKG_VERSION"),
        body.len()
    );
    for (name, value) in extra_headers {
        let lower = name.to_ascii_lowercase();
        if matches!(lower.as_str(), "host" | "content-length" | "connection") {
            return Err(HttpError::InvalidUrl(
                "an extra header may not override a transport-owned header",
            ));
        }
        if name.bytes().any(|b| b < 0x20 || b == 0x7f)
            || value.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            return Err(HttpError::InvalidUrl(
                "header names and values must not carry control characters",
            ));
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    // Connection: close means the peer hangs up after the body, so reading
    // to EOF is the framing; the byte cap keeps a broken peer bounded.
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if raw.len() + n > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge(MAX_RESPONSE_BYTES));
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    parse_response(&raw)
}

/// Split an absolute http:// URL into host, port and path.
fn parse_http_url(url: &str) -> Result<(String, u16, String), HttpError> {
    let rest = if let Some(r) = url.strip_prefix("http://") {
        r
    } else if url.starts_with("https://") {
        return Err(HttpError::HttpsUnsupported);
    } else {
        return Err(HttpError::InvalidUrl(
            "the endpoint must be an absolute http:// URL",
        ));
    };
    if rest.is_empty() || rest.starts_with('/') {
        return Err(HttpError::InvalidUrl("the endpoint has no authority"));
    }
    let split = rest.find('/');
    let (authority, path) = match split {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() || authority.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(HttpError::InvalidUrl("the authority is not a plain host"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| HttpError::InvalidUrl("the port does not fit a u16"))?;
            (h.to_string(), port)
        }
        _ => (authority.to_string(), 80),
    };
    Ok((host, port, path))
}

/// Parse a raw HTTP/1.1 response: status line, headers, then the body
/// framed by Content-Length or chunked coding (a bare close-delimited body
/// is accepted too, matching the Connection: close request).
fn parse_response(raw: &[u8]) -> Result<HttpResponse, HttpError> {
    let head_end = find_subslice(raw, b"\r\n\r\n").ok_or(HttpError::Protocol(
        "the response has no complete header block",
    ))?;
    let head = std::str::from_utf8(&raw[..head_end])
        .map_err(|_| HttpError::Protocol("the header block is not ASCII"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(HttpError::Protocol("the response has no status line"))?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(HttpError::Protocol(
            "the status line carries no numeric code",
        ))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                content_length = value.parse::<usize>().ok();
            }
            "transfer-encoding" => {
                chunked = value.to_ascii_lowercase().contains("chunked");
            }
            _ => {}
        }
    }

    let body_bytes = &raw[head_end + 4..];
    let body = if chunked {
        decode_chunked(body_bytes)?
    } else if let Some(len) = content_length {
        if body_bytes.len() < len {
            return Err(HttpError::Protocol(
                "the body is shorter than the declared Content-Length",
            ));
        }
        body_bytes[..len].to_vec()
    } else {
        body_bytes.to_vec()
    };
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(HttpError::TooLarge(MAX_RESPONSE_BYTES));
    }
    Ok(HttpResponse { status, body })
}

/// Decode a chunked body: size-prefixed hex chunks, the zero chunk, then
/// the trailer block. Chunk extensions after ';' are ignored, the exact
/// framing this client's stub-server tests exercise.
fn decode_chunked(data: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    loop {
        let line_end = find_subslice(&data[cursor..], b"\r\n")
            .ok_or(HttpError::Protocol("the chunked body lacks a size line"))?
            + cursor;
        let size_text = std::str::from_utf8(&data[cursor..line_end])
            .map_err(|_| HttpError::Protocol("the chunk size line is not ASCII"))?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| HttpError::Protocol("the chunk size is not hexadecimal"))?;
        cursor = line_end + 2;
        if size == 0 {
            break;
        }
        if cursor + size > data.len() {
            return Err(HttpError::Protocol("a chunk is truncated"));
        }
        if out.len() + size > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge(MAX_RESPONSE_BYTES));
        }
        out.extend_from_slice(&data[cursor..cursor + size]);
        cursor += size;
        if data.len() < cursor + 2 || &data[cursor..cursor + 2] != b"\r\n" {
            return Err(HttpError::Protocol(
                "a chunk is not terminated by a bare CRLF",
            ));
        }
        cursor += 2;
    }
    Ok(out)
}

/// The first index of `needle` in `hay`, as a slice search without any
/// dependency.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}
