"""Measure Warden deterministic scan latency over the full corpus."""

import asyncio
import json
import statistics
from pathlib import Path

from warden.engine import WardenEngine

ROOT = Path(__file__).resolve().parent


def _load(name: str) -> list[dict]:
    out = []
    p = ROOT / "corpus" / name
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


async def main() -> None:
    engine = WardenEngine()
    entries = _load("attacks.jsonl") + _load("benign.jsonl")

    # warm-up (compile patterns / JIT paths) — not counted
    for e in entries[:5]:
        await engine.scan(e["payload"], context=e.get("context", {}))

    lat = []
    for e in entries:
        v = await engine.scan(e["payload"], context=e.get("context", {}))
        lat.append(v.latency_ms)

    lat.sort()
    n = len(lat)
    print(f"payloads scanned: {n}")
    print(f"min     : {lat[0]:.2f} ms")
    print(f"p50     : {statistics.median(lat):.2f} ms")
    print(f"p95     : {lat[int(n * 0.95)]:.2f} ms")
    print(f"p99     : {lat[int(n * 0.99)]:.2f} ms")
    print(f"max     : {lat[-1]:.2f} ms")
    print(f"mean    : {statistics.mean(lat):.2f} ms")
    print(f"under 1s: {sum(1 for x in lat if x < 1000)}/{n}")


if __name__ == "__main__":
    asyncio.run(main())
