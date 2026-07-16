//! Shared helpers for the sync/device integration tests.
//!
//! Each integration-test binary compiles this module fresh, so a helper used by
//! only some binaries reads as dead code in the others — allow it here.
#![allow(dead_code)]

use sshvault::record::{Host, Kind};
use sshvault::vault::Vault;

/// Boot the relay on an ephemeral port; return its base URL.
pub async fn start_relay(db_path: String) -> String {
    // bind :0 to get a free port, then hand the address to serve() (it rebinds).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // serve() rebinds; race window is negligible for a test
    tokio::spawn(async move {
        sshvault::relay::serve(&addr.to_string(), &db_path)
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    for _ in 0..100 {
        if client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            return base;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("relay did not come up");
}

pub fn host(alias: &str, hostname: &str, port: u16) -> Host {
    Host {
        alias: alias.into(),
        hostname: Some(hostname.into()),
        port: Some(port),
        ..Default::default()
    }
}

/// Sync a device until a full round makes no local progress (push+pull settle).
pub async fn drain(v: &mut Vault) {
    for _ in 0..10 {
        let (pushed, pulled) = sshvault::sync::sync_once(v).await.unwrap();
        if pushed == 0 && pulled == 0 {
            return;
        }
    }
}

pub fn hosts_sorted(v: &Vault) -> Vec<Host> {
    let mut h: Vec<Host> = v
        .list::<Host>(Kind::Host)
        .into_iter()
        .map(|(_, h)| h)
        .collect();
    h.sort_by(|a, b| a.alias.cmp(&b.alias));
    h
}
