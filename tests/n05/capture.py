"""N05 worker adapter of toolchain/src/run-qemu-verification.py capture_guest semantics."""
import os
import selectors
import signal
import subprocess
import time


def worker(command, request, timeout, max_bytes, preexec=None):
    if timeout <= 0 or max_bytes <= 0 or len(request) > 4096:
        raise ValueError("positive capture limits and <=4096 input bytes required")
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    reason = None
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True, preexec_fn=preexec)
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selected:
        selected.register(process.stdout, selectors.EVENT_READ, "stdout")
        selected.register(process.stderr, selectors.EVENT_READ, "stderr")
        try:
            # This fixed <=4096-byte request fits a fresh POSIX pipe. Never stream unbounded input.
            try:
                process.stdin.write(request)
                process.stdin.close()
            except BrokenPipeError:
                reason = "stdin_closed"
            while selected.get_map() and reason is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "timeout"
                    break
                for key, _ in selected.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    available = max_bytes - sum(map(len, streams.values()))
                    streams[key.data].extend(chunk[:available])
                    if len(chunk) > available:
                        reason = "output_limit"
                        break
            if reason is None:
                try:
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = "timeout"
        finally:
            # On an incomplete capture, clean the group before reaping its leader. A completed
            # leader is never signaled after wait (its PID may already have been reused).
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    reason = "cleanup_denied"
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                reason = "reap_timeout"
            for stream in (process.stdin, process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()
    return {"stdout": bytes(streams["stdout"]), "stderr": bytes(streams["stderr"]),
            "returncode": process.returncode, "stop_reason": reason,
            "retained_bytes": sum(map(len, streams.values()))}
