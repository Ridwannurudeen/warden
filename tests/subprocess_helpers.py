"""Helpers for timing isolated Python operations after interpreter startup."""

from pathlib import Path
import queue
import subprocess
import sys
import threading

REPO_ROOT = Path(__file__).resolve().parents[1]
STARTUP_TIMEOUT_SECONDS = 10
READY_SENTINEL = "WARDEN_TEST_WORKER_READY\n"
DONE_SENTINEL = "WARDEN_TEST_WORKER_DONE "
IPC_GRACE_SECONDS = 5


def run_python_operation_after_startup(
    *,
    setup: str,
    operation: str,
    timeout: float,
) -> None:
    worker = (
        "import sys\n"
        "import time\n"
        f"{setup.rstrip()}\n"
        f"sys.stdout.write({READY_SENTINEL!r})\n"
        "sys.stdout.flush()\n"
        "if sys.stdin.readline() != 'RUN\\n':\n"
        "    raise RuntimeError('test worker did not receive RUN command')\n"
        "started = time.perf_counter()\n"
        f"{operation.rstrip()}\n"
        "elapsed = time.perf_counter() - started\n"
        f"sys.stdout.write({DONE_SENTINEL!r} + repr(elapsed) + '\\n')\n"
        "sys.stdout.flush()\n"
    )
    command = [sys.executable, "-u", "-c", worker]
    process = subprocess.Popen(
        command,
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )

    ready_lines: queue.Queue[str] = queue.Queue(maxsize=1)
    reader = threading.Thread(
        target=lambda: ready_lines.put(process.stdout.readline()),
        daemon=True,
    )
    reader.start()

    try:
        try:
            ready = ready_lines.get(timeout=STARTUP_TIMEOUT_SECONDS)
        except queue.Empty:
            process.kill()
            process.wait()
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            raise subprocess.TimeoutExpired(
                command,
                STARTUP_TIMEOUT_SECONDS,
                output=stdout,
                stderr=stderr,
            ) from None

        if ready != READY_SENTINEL:
            if process.poll() is None:
                process.kill()
            process.wait()
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            raise subprocess.CalledProcessError(
                process.returncode or 1,
                command,
                output=ready + stdout,
                stderr=stderr,
            )

        done_lines: queue.Queue[str] = queue.Queue(maxsize=1)
        done_reader = threading.Thread(
            target=lambda: done_lines.put(process.stdout.readline()),
            daemon=True,
        )
        done_reader.start()
        process.stdin.write("RUN\n")
        process.stdin.flush()

        try:
            done = done_lines.get(timeout=timeout + IPC_GRACE_SECONDS)
        except queue.Empty:
            process.kill()
            process.wait()
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            raise subprocess.TimeoutExpired(
                command,
                timeout,
                output=ready + stdout,
                stderr=stderr,
            ) from None

        if not done.startswith(DONE_SENTINEL):
            process.wait(timeout=STARTUP_TIMEOUT_SECONDS)
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            raise subprocess.CalledProcessError(
                process.returncode or 1,
                command,
                output=ready + done + stdout,
                stderr=stderr,
            )

        elapsed = float(done.removeprefix(DONE_SENTINEL).strip())
        if not 0 <= elapsed <= timeout:
            if process.poll() is None:
                process.kill()
            process.wait()
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            raise subprocess.TimeoutExpired(
                command,
                timeout,
                output=ready + done + stdout,
                stderr=stderr,
            )

        process.wait(timeout=STARTUP_TIMEOUT_SECONDS)
        stdout = process.stdout.read()
        stderr = process.stderr.read()
        if process.returncode:
            raise subprocess.CalledProcessError(
                process.returncode,
                command,
                output=ready + done + stdout,
                stderr=stderr,
            )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
