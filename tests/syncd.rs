//! `syncd` gate: a device running the sync daemon must converge on remote
//! pushes without any manual `sync` — driven by the relay's WS notification,
//! not the (30 s) fallback tick, so the whole test runs in well under that.

use sshvault::record::{Host, Kind};
use std::time::Duration;
use tempfile::TempDir;

mod common;
use common::{drain, host, hosts_sorted, make_devices, start_relay};

#[tokio::test]
async fn daemon_follows_remote_pushes() {
    // Push the fallback poll far past the test's own timeout, so the ONLY thing
    // that can converge the follower in time is a live WS notification — a
    // broken notify path (or a flapping reconnect that resyncs on every retry)
    // can no longer mask itself behind the periodic tick.
    std::env::set_var("SSHVAULT_SYNCD_POLL_SECS", "3600");

    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("relay.db").display().to_string();
    let relay = start_relay(db).await;
    let mut devs = make_devices(tmp.path(), 2, &relay).await;
    let mut follower = devs.pop().unwrap(); // dev1 runs the daemon
    let mut author = devs.pop().unwrap(); // dev0 makes edits

    // Every daemon round reports (pulled, current hosts) back to the test.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(usize, Vec<Host>)>();
    let daemon = tokio::spawn(async move {
        sshvault::sync::syncd(&mut follower, move |v, _pushed, pulled| {
            let _ = tx.send((pulled, hosts_sorted(v)));
        })
        .await
        .unwrap();
    });

    // The daemon's first round fires before it attaches to the WS; wait for it,
    // then give the (in-process, localhost) WS connect a beat to complete.
    recv(&mut rx).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    // A remote push must reach the follower via notification alone.
    author
        .add(
            Kind::Host,
            "alias",
            "web",
            &host("web", "web.example.com", 22),
        )
        .unwrap();
    drain(&mut author).await;
    let hosts = wait_for_pull(&mut rx).await;
    assert_eq!(hosts.len(), 1, "daemon pulled the new host");
    assert_eq!(hosts[0].alias, "web");
    assert_eq!(hosts[0].port, Some(22));

    // And it must keep following — a second edit converges the same way.
    author
        .edit(
            Kind::Host,
            "alias",
            "web",
            &host("web", "web.example.com", 2222),
        )
        .unwrap();
    drain(&mut author).await;
    let hosts = wait_for_pull(&mut rx).await;
    assert_eq!(hosts[0].port, Some(2222), "daemon pulled the edit");

    daemon.abort();
}

/// Next round report, or panic after a timeout well below the fallback tick.
async fn recv(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<(usize, Vec<Host>)>,
) -> (usize, Vec<Host>) {
    tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("daemon round within 15s")
        .expect("daemon alive")
}

/// Skip rounds that pulled nothing (e.g. echo of our own push) and return the
/// host state from the first round that actually pulled entries.
async fn wait_for_pull(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<(usize, Vec<Host>)>,
) -> Vec<Host> {
    loop {
        let (pulled, hosts) = recv(rx).await;
        if pulled > 0 {
            return hosts;
        }
    }
}
