//! Actual executable group-option controls and the local multi-receiver oracle.

use std::io::Write;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct OwnedChild(Option<Child>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut()
            && child.try_wait().ok().flatten().is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn unique_path(label: &str) -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    base.join(format!(
        "ffw-source-group-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn rejected(args: &[&str], reason: &str) {
    let mut child = OwnedChild(Some(
        Command::new(env!("CARGO_BIN_EXE_franken-speaker"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn source option control"),
    ));
    // If parsing accidentally admits these options, a valid key and future GO
    // make progress possible; EOF alone cannot masquerade as option rejection.
    if let Some(mut stdin) = child.0.as_mut().unwrap().stdin.take() {
        let _ = writeln!(stdin, "KEY {}\nGO 3000000000000000000", "07".repeat(32));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child
            .0
            .as_mut()
            .unwrap()
            .try_wait()
            .expect("poll child")
            .is_some()
        {
            break;
        }
        assert!(Instant::now() < deadline, "option control timed out");
        thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .0
        .take()
        .unwrap()
        .wait_with_output()
        .expect("collect child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains(reason),
        "expected {reason:?}; stdout={stdout}\nstderr={stderr}"
    );
    assert!(!stdout.contains("\"ready\""), "unexpected ready: {stdout}");
}

#[test]
fn group_sender_rejects_invalid_peers_before_ready_or_media() {
    let sockets: Vec<_> = (0..18)
        .map(|_| {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("bind local observer");
            socket.set_nonblocking(true).unwrap();
            socket
        })
        .collect();
    let addrs: Vec<_> = sockets
        .iter()
        .map(|socket| socket.local_addr().unwrap())
        .collect();
    let peer = |id: usize, media: usize, control: usize| {
        format!("{id}@{}@{}", addrs[media], addrs[control])
    };
    let cases = [
        (
            format!("{},{}", peer(1, 0, 1), peer(1, 2, 3)),
            "duplicate peer id or aliased endpoint",
        ),
        (
            format!("{},{}", peer(1, 0, 1), peer(2, 1, 3)),
            "duplicate peer id or aliased endpoint",
        ),
        (format!("1@192.0.2.1:5000@{}", addrs[1]), "loopback"),
        (
            (0..9)
                .map(|i| peer(i + 1, i * 2, i * 2 + 1))
                .collect::<Vec<_>>()
                .join(","),
            "peer count outside bound",
        ),
    ];
    let missing_source = unique_path("not-opened");
    let source = missing_source.to_str().unwrap();
    for (peers, reason) in cases {
        rejected(
            &[
                "--source-loopback-send",
                "--input",
                source,
                "--codec",
                "mp3",
                "--peers",
                &peers,
                "--timeout-ms",
                "3000",
                "--stream-id",
                "7",
                "--epoch",
                "1",
            ],
            reason,
        );
        assert!(!missing_source.exists());
        for socket in &sockets {
            match socket.recv_from(&mut [0_u8; 1500]) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("invalid options caused network activity: {other:?}"),
            }
        }
    }
}

#[test]
fn group_receiver_rejects_invalid_peer_before_output_creation() {
    for (peer, reason) in [
        ("0", "peer id outside bound"),
        ("16777216", "peer id outside bound"),
        ("-1", "invalid peer id"),
    ] {
        let output = unique_path("no-output");
        rejected(
            &[
                "--source-loopback-receive",
                "--output",
                output.to_str().unwrap(),
                "--peer-id",
                peer,
                "--timeout-ms",
                "3000",
                "--stream-id",
                "7",
                "--epoch",
                "1",
            ],
            reason,
        );
        assert!(!output.exists(), "invalid peer created output");
    }
}

#[test]
fn source_group_processes_match_pcm_and_isolate_wrong_key() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_dir.parent().unwrap().parent().unwrap();
    let output = Command::new("python3")
        .arg(workspace.join("tests/source_runtime/run_group.py"))
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_franken-speaker"))
        .arg("--output-dir")
        .arg(unique_path("oracle"))
        .output()
        .expect("start the real group-process PCM oracle");
    let stdout = String::from_utf8(output.stdout).expect("runner stdout is UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    assert!(
        output.status.success(),
        "group runner failed: {stderr}\n{stdout}"
    );
    let summaries: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("FFW_SOURCE_GROUP: "))
        .collect();
    assert_eq!(summaries.len(), 1, "expected one group summary: {stdout}");
    let report: serde_json::Value =
        serde_json::from_str(summaries[0]).expect("group summary is JSON");
    assert_eq!(report["planned"], 3);
    assert_eq!(report["passed"], 3);
    assert_eq!(report["failed"], 0);
    let results = report["results"].as_array().expect("case results");
    assert_eq!(results.len(), 3);
    for result in results {
        assert_eq!(result["status"], "passed");
    }
}
