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
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    drop(stream);
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "client never connected to the test listener"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("test listener failed: {error}"),
            }
        }
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let error = client
        .get(format!("https://{address}/"))
        .send()
        .await
        .unwrap_err();
    server.join().unwrap();
    assert!(
        error.is_connect(),
        "expected a connect error, got {error:?}"
    );
    assert_eq!(
        classify(&anyhow::Error::new(error)),
        FailureClass::TemporaryExternal
    );
}
