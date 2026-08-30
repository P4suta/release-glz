use release_glz::failure::{FailureClass, classified, classify, with_default_class};

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

#[tokio::test]
async fn connection_errors_are_classified_by_type_not_message_text() {
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let error = client.get("http://127.0.0.1:1/").send().await.unwrap_err();
    assert!(error.is_connect());
    assert_eq!(
        classify(&anyhow::Error::new(error)),
        FailureClass::TemporaryExternal
    );
}
