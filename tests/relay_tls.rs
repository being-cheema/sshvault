//! The relay can terminate TLS itself (rustls) when given a cert + key, so a
//! bare deployment is safe without a reverse proxy. This gate proves an HTTPS
//! listener actually comes up and serves, and that a client which trusts the
//! cert can reach it over TLS.

use std::io::Write;

/// Generate a self-signed cert for `localhost`/127.0.0.1, write cert+key PEM to
/// `dir`, and return their paths.
fn self_signed(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("generate self-signed cert");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::File::create(&cert_path)
        .unwrap()
        .write_all(cert_pem.as_bytes())
        .unwrap();
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(key_pem.as_bytes())
        .unwrap();
    (cert_path, key_path)
}

#[tokio::test]
async fn relay_serves_over_https() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = self_signed(dir.path());
    let cert_pem = std::fs::read(&cert_path).unwrap();

    // free port, then hand the address to serve() (it rebinds)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let db_path = dir.path().join("relay.db").to_string_lossy().into_owned();
    tokio::spawn(async move {
        sshvault::relay::serve(
            &addr.to_string(),
            &db_path,
            Some(sshvault::relay::TlsPaths {
                cert: cert_path,
                key: key_path,
            }),
        )
        .await
        .unwrap();
    });

    // a client that trusts our self-signed cert must reach the relay over HTTPS
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&cert_pem).unwrap())
        .build()
        .unwrap();

    let url = format!("https://localhost:{}/healthz", addr.port());
    let mut ok = false;
    for _ in 0..100 {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() && resp.text().await.unwrap_or_default() == "ok" {
                ok = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(ok, "relay did not serve /healthz over HTTPS");
}
