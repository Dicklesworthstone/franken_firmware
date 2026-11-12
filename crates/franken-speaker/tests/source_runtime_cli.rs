//! Actual prebuilt-binary local-process source and PCM oracle. No nested Cargo.

use std::io::{BufRead, BufReader, Write};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn wait_child(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "child did not exit within five seconds"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn stop_before_go_and_expired_anchor_emit_no_media() {
    for (command, expected_exit) in [("STOP\n", 0), ("GO 1\n", 2)] {
        let media = UdpSocket::bind("127.0.0.1:0").unwrap();
        media
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let control = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut child = OwnedChild(
            Command::new(env!("CARGO_BIN_EXE_franken-speaker"))
                .args([
                    "--source-loopback-send",
                    "--input",
                    "/not-opened-before-go",
                    "--codec",
                    "mp3",
                    "--media",
                    &media.local_addr().unwrap().to_string(),
                    "--control",
                    &control.local_addr().unwrap().to_string(),
                    "--timeout-ms",
                    "3000",
                    "--stream-id",
                    "7",
                    "--epoch",
                    "1",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn local sender"),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stdin = child.0.stdin.as_mut().unwrap();
        writeln!(stdin, "KEY {}", "07".repeat(32)).unwrap();
        stdin.flush().unwrap();
        let ready = rx
            .recv_timeout(Duration::from_secs(3))
            .expect("bounded ready")
            .unwrap();
        let ready: serde_json::Value = serde_json::from_str(&ready).unwrap();
        assert_eq!(ready["event"], "ready");
        let stdin = child.0.stdin.as_mut().unwrap();
        stdin.write_all(command.as_bytes()).unwrap();
        stdin.flush().unwrap();
        let status = wait_child(&mut child.0);
        assert_eq!(status.code(), Some(expected_exit));
        if expected_exit == 0 {
            let stopped = rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&stopped).unwrap()["event"],
                "stopped"
            );
        }
        assert!(
            media.recv_from(&mut [0_u8; 1500]).is_err(),
            "negative emitted a media datagram"
        );
    }
}

#[test]
fn source_loopback_processes_match_independent_pcm_and_reject_wrong_key() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_dir.parent().unwrap().parent().unwrap();
    let runner = workspace.join("tests/source_runtime/run_loopback.py");
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let output_dir = base.join(format!(
        "ffw-source-loopback-{}-{nonce}",
        std::process::id()
    ));
    let output = Command::new("python3")
        .arg(runner)
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_franken-speaker"))
        .arg("--output-dir")
        .arg(&output_dir)
        .output()
        .expect("start the real-process PCM oracle");
    let stdout = String::from_utf8(output.stdout).expect("runner stdout is UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}");
    assert!(output.status.success(), "runner failed: {stderr}\n{stdout}");
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("FFW_SOURCE_LOOPBACK: "))
        .expect("runner summary is present");
    let report: serde_json::Value = serde_json::from_str(line).expect("runner summary is JSON");
    assert_eq!(report["planned"], 3);
    assert_eq!(report["passed"], 3);
    assert_eq!(report["failed"], 0);
    assert_eq!(report["results"].as_array().unwrap().len(), 3);
    for result in report["results"].as_array().unwrap() {
        assert_eq!(result["status"], "passed");
    }
}
