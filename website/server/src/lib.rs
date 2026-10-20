//! Static file server for the Zola-built KiwiCaptcha product website.
//!
//! The website ships no JavaScript, so the Content-Security-Policy the
//! server stamps on every response does not admit scripts at all: a
//! violated policy here means the build produced a script, not that a
//! client did something unexpected. Unknown paths fall back to the
//! built 404 page (kept at the 404 status), and directory traversal is
//! delegated to ServeDir.

use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

/// Returns the website root: the KIWI_WEBSITE_ROOT environment variable
/// when set, otherwise the Zola output directory relative to this crate.
pub fn website_root() -> PathBuf {
    match std::env::var("KIWI_WEBSITE_ROOT") {
        Ok(root) if !root.trim().is_empty() => PathBuf::from(root),
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../zola/public"),
    }
}

/// Rewrites the body of every 404 to the site's built 404 page so an
/// unknown path stays on-brand and script-free at the right status.
#[derive(Clone)]
struct NotFoundPageLayer {
    page: Box<[u8]>,
}

impl NotFoundPageLayer {
    fn new(page: PathBuf) -> Self {
        let bytes = std::fs::read(&page).unwrap_or_else(|error| {
            panic!("the built site must contain {}: {error}", page.display())
        });
        Self { page: bytes.into() }
    }
}

impl<S> Layer<S> for NotFoundPageLayer {
    type Service = NotFoundPage<S>;
    fn layer(&self, inner: S) -> Self::Service {
        NotFoundPage {
            inner,
            page: self.page.clone(),
        }
    }
}

#[derive(Clone)]
struct NotFoundPage<S> {
    inner: S,
    page: Box<[u8]>,
}

impl<S> Service<Request> for NotFoundPage<S>
where
    S: Service<Request, Response = Response, Error = std::convert::Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let mut service = self.inner.clone();
        let page = self.page.clone();
        Box::pin(async move {
            let mut response = service.call(request).await?;
            if response.status() == StatusCode::NOT_FOUND {
                let html =
                    HeaderValue::from_str("text/html; charset=utf-8").expect("static content type");
                *response.body_mut() = axum::body::Body::from(axum::body::Bytes::from(page));
                response.headers_mut().insert(header::CONTENT_TYPE, html);
                response.headers_mut().remove(header::CONTENT_LENGTH);
            }
            Ok(response)
        })
    }
}

/// Builds the application serving `root`.
pub fn app(root: &Path) -> Router {
    let serve = ServeDir::new(root).append_index_html_on_directories(true);
    let router = Router::new()
        .route("/healthz", get(health))
        .fallback_service(serve)
        .layer(NotFoundPageLayer::new(root.join("404.html")));
    // Security headers sit outermost so every response — including the
    // rewritten 404 page — carries them. script-src stays empty: the
    // site is JavaScript-free by construction, and any script the build
    // emits must fail to load rather than run.
    let csp = "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; \
               connect-src 'none'; media-src 'none'; object-src 'none'; script-src 'none'; \
               form-action 'none'; base-uri 'none'; frame-ancestors 'none'";
    let headers: [(HeaderName, &str); 3] = [
        (header::CONTENT_SECURITY_POLICY, csp),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "strict-origin-when-cross-origin"),
    ];
    let mut out = router;
    for (name, value) in headers {
        out = out.layer(SetResponseHeaderLayer::overriding(
            name,
            HeaderValue::from_static(value),
        ));
    }
    out
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "kiwicaptcha website server\n")
}

/// Entry point: bind, announce and serve until interrupted.
pub async fn run() {
    let root = website_root();
    if !root.join("index.html").exists() {
        eprintln!(
            "no built website at {}; run website/build.sh first (or set KIWI_WEBSITE_ROOT)",
            root.display()
        );
        std::process::exit(1);
    }
    let bind: std::net::SocketAddr = std::env::var("KIWI_WEBSITE_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8090".to_string())
        .parse()
        .expect("KIWI_WEBSITE_BIND must be a socket address");
    let router = app(&root);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .expect("failed to bind the website server");
    println!(
        "kiwicaptcha website: serving {} on http://{bind}",
        root.display()
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("website server error");
}
