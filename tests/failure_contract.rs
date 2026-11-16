use release_glz::failure::{FailureClass, classified, classify, with_default_class};
use release_glz_test_support::http::FakeServer;

#[test]
fn an_explicit_internal_class_is_never_replaced_by_a_boundary_default() {
    let explicit = classified(FailureClass::Internal, "explicit internal failure");
    let preserved = with_default_class(explicit, FailureClass::TemporaryExternal);
    assert_eq!(classify(&preserved), FailureClass::Internal);

    let untyped = with_default_class(
        anyhow::anyhow!("untyped boundary failure"),
        FailureClass::TemporaryExternal,
    );
    assert_eq!(classify(&untyped), FailureClass::TemporaryExternal);
}

/// A class attached at a command boundary keeps every context and cause beneath it, so a diagnostic says which check refused.
#[test]
fn a_classified_failure_keeps_every_cause() {
    let error = anyhow::anyhow!("GitHub OIDC URLs must use HTTPS")
        .context("release approval OIDC verification failed");

    let defaulted = with_default_class(error, FailureClass::PolicyOrApproval);
    assert_eq!(classify(&defaulted), FailureClass::PolicyOrApproval);
    assert_eq!(
        defaulted.to_string(),
        "release approval OIDC verification failed: GitHub OIDC URLs must use HTTPS"
    );

    let explicit = classified(
        FailureClass::UsageOrConfig,
        anyhow::anyhow!("no such file").context("manifest is missing"),
    );
    assert_eq!(explicit.to_string(), "manifest is missing: no such file");
    assert_eq!(
        classified(FailureClass::Hook, "hook timed out").to_string(),
        "hook timed out"
    );
}

#[tokio::test]
async fn connection_errors_are_classified_by_type_not_message_text() {
    // The server closes the connection before the TLS handshake, which ends the request without a client timeout.
    let mut server = FakeServer::start();
    server.hang_up();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let error = client
        .get(format!("https://{}/", server.address()))
        .send()
        .await
        .unwrap_err();
    server.finish();
    assert_eq!(
        server.connections(),
        1,
        "client never connected to the test listener"
    );
    assert!(
        error.is_connect(),
        "expected a connect error, got {error:?}"
    );
    assert_eq!(
        classify(&anyhow::Error::new(error)),
        FailureClass::TemporaryExternal
    );
}
