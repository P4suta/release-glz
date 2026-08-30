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
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let error = reqwest::get(format!("http://{address}/"))
        .await
        .unwrap_err();
    assert!(error.is_connect());
    assert_eq!(
        classify(&anyhow::Error::new(error)),
        FailureClass::TemporaryExternal
    );
}
