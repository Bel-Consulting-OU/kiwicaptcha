//! Integration tests against the real application router: index
//! resolution, MIME, the on-brand script-free 404, the security headers
//! (including a CSP that admits no scripts) and traversal refusal.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use kiwicaptcha_website::app;
use tower::ServiceExt;

fn fixture() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kiwi-website-serve-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(dir.join("css")).expect("fixture dirs");
    std::fs::write(
        dir.join("index.html"),
        "<!DOCTYPE html><html lang=\"en\"><head><title>KiwiCaptcha</title>\
         <link rel=\"stylesheet\" href=\"/css/kiwi.css\"></head>\
         <body><main id=\"main\">Your application.</main></body></html>",
    )
    .expect("fixture index");
    std::fs::write(dir.join("css/kiwi.css"), "body{background:#F3F5EF}").expect("fixture css");
    std::fs::write(
        dir.join("404.html"),
        "<!DOCTYPE html><html lang=\"en\"><body><main>No such page</main></body></html>",
    )
    .expect("fixture 404");
    dir
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

#[tokio::test]
async fn index_resolves_at_root() {
    let dir = fixture();
    let response = app(&dir)
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_string(response).await.contains("Your application."));
}

#[tokio::test]
async fn css_serves_with_stylesheet_mime() {
    let dir = fixture();
    let response = app(&dir)
        .oneshot(
            Request::builder()
                .uri("/css/kiwi.css")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response.headers()[header::CONTENT_TYPE]
        .to_str()
        .expect("mime");
    assert!(
        content_type.starts_with("text/css"),
        "unexpected mime {content_type}"
    );
}

#[tokio::test]
async fn unknown_path_serves_the_built_404_page_at_404() {
    let dir = fixture();
    let response = app(&dir)
        .oneshot(
            Request::builder()
                .uri("/no/such/page")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_string(response).await;
    assert!(body.contains("No such page"));
    assert!(
        !body.contains("<script"),
        "the 404 page must stay script-free"
    );
}

#[tokio::test]
async fn every_response_carries_the_script_free_csp_and_nosniff() {
    let dir = fixture();
    let response = app(&dir)
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("serve");
    let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .expect("csp");
    assert!(
        csp.contains("script-src 'none'"),
        "csp must admit no scripts: {csp}"
    );
    assert!(csp.contains("default-src 'none'"));
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    assert_eq!(
        response.headers()[header::REFERRER_POLICY],
        "strict-origin-when-cross-origin"
    );
}

#[tokio::test]
async fn traversal_style_paths_do_not_escape_the_root() {
    let dir = fixture();
    let response = app(&dir)
        .oneshot(
            Request::builder()
                .uri("/..%2f..%2fCargo.toml")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_endpoint_answers_ok() {
    let dir = fixture();
    let response = app(&dir)
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("serve");
    assert_eq!(response.status(), StatusCode::OK);
}
