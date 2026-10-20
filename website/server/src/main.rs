//! The KiwiCaptcha website server binary. Everything lives in the
//! library so the integration tests exercise the real router.

#[tokio::main]
async fn main() {
    kiwicaptcha_website::run().await;
}
