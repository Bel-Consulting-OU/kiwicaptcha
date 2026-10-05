//! Transport-level tests for the std-only HTTP client: both body framings
//! a real deployment answers with, the https refusal with its documented
//! remedy, and the injection guards.

use kiwicaptcha_solver::http::{post_json, HttpError};
use std::io::{Read, Write};
use std::net::TcpListener;

/// Accept exactly one connection, drain its request, answer with `raw`.
fn spawn_once(raw: &'static [u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the stub binds a free port");
    let addr = listener.local_addr().expect("the stub reports its address");
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the stub accepts once");
        let mut drain = [0u8; 4096];
        let _ = stream.read(&mut drain);
        let _ = stream.write_all(raw);
    });
    format!("http://{addr}/challenge")
}

#[test]
fn content_length_bodies_are_read_verbatim() {
    let url = spawn_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
    let response = post_json(&url, "{}", &[]).expect("the POST succeeds");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello");
}

#[test]
fn chunked_bodies_are_decoded() {
    let url = spawn_once(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
          5\r\nhello\r\n3\r\n wo\r\n2\r\nrl\r\n1\r\nd\r\n0\r\n\r\n",
    );
    let response = post_json(&url, "{}", &[]).expect("the POST succeeds");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello world");
}

#[test]
fn extra_headers_ride_the_request() {
    // The stub echoes nothing, so the assertion is structural: the request
    // with a cookie header is accepted (no guard fired) and answered.
    let url =
        spawn_once(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let response = post_json(
        &url,
        "{}",
        &[("Cookie".to_string(), "session=abc".to_string())],
    )
    .expect("the POST with an extra header succeeds");
    assert_eq!(response.status, 204);
    assert!(response.body.is_empty());
}

#[test]
fn https_is_refused_with_the_documented_remedy() {
    let err = post_json("https://captcha.example/challenge", "{}", &[])
        .expect_err("https must be refused");
    assert!(matches!(err, HttpError::HttpsUnsupported));
    assert!(
        err.to_string().contains("proxy"),
        "the error names the remedy: {err}"
    );
}

#[test]
fn non_http_schemes_and_bare_hosts_are_refused() {
    assert!(matches!(
        post_json("captcha.example/challenge", "{}", &[]),
        Err(HttpError::InvalidUrl(_))
    ));
    assert!(matches!(
        post_json("ftp://captcha.example", "{}", &[]),
        Err(HttpError::InvalidUrl(_))
    ));
}

#[test]
fn transport_owned_headers_cannot_be_overridden() {
    for name in ["Host", "Content-Length", "Connection", "host"] {
        // A fresh one-shot stub per round: the guard must fire before any
        // connection is even made.
        let url = spawn_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let err = post_json(&url, "{}", &[(name.to_string(), "evil".to_string())])
            .expect_err("the guard must fire");
        assert!(matches!(err, HttpError::InvalidUrl(_)), "{name}: {err}");
    }
}

#[test]
fn control_characters_in_headers_are_refused() {
    let url = spawn_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let err = post_json(
        &url,
        "{}",
        &[("X-Test".to_string(), "a\r\nHost: evil".to_string())],
    )
    .expect_err("header injection must be refused");
    assert!(matches!(err, HttpError::InvalidUrl(_)), "{err}");
}

#[test]
fn a_dead_port_is_a_transport_error() {
    // Bind a port, note it, close the listener: nothing listens there.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let err = post_json(&format!("http://{addr}/challenge"), "{}", &[])
        .expect_err("a dead port must fail");
    assert!(matches!(err, HttpError::Io(_)), "{err}");
}
