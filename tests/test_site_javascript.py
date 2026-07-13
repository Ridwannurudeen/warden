"""Run dependency-free browser JavaScript unit tests under Node."""

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_site_javascript():
    test_files = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "tests" / "js").glob("*.test.js"))
    completed = subprocess.run(
        ["node", "--test", *test_files],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
