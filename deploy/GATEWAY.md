# Warden Gateway

Warden Gateway is a fail-closed HTTP sidecar for a single protected agent origin. It scans each
non-empty UTF-8 request body with the local Warden engine before forwarding the request. An
explicit `BLOCK`, scanner failure, invalid scanner response, invalid UTF-8 body, oversized request,
upstream failure, or proxy loop never reaches the upstream. `SANITIZE` forwards only the sanitized
body.

Hosted paid mode remains unsupported for enforcement deployments because the gateway does not
settle x402 payments. Run `--mode local`.

## Docker

Build the gateway from the reviewed checkout:

```bash
docker build -f deploy/Dockerfile.gateway -t warden-gateway .
docker run --rm \
  --name warden-gateway \
  --network agent-stack \
  --publish 127.0.0.1:8787:8787 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --volume warden-gateway-state:/var/lib/warden-gateway \
  warden-gateway \
  --upstream http://my-agent:8000 \
  --mode local
```

The named volume retains the local signing key and scanner state. The container runs as the
unprivileged `warden-gateway` user, publishes only on loopback, reports container health through
`/healthz`, and drains active requests for up to 30 seconds after `SIGTERM`.

For the sidecar topology, set the protected agent image and start the checked-in Compose manifest:

```bash
export WARDEN_AGENT_IMAGE=registry.example/agent:reviewed-tag
docker compose -f deploy/docker-compose.gateway.yml up --build
```

The internal `gateway-boundary` network connects the gateway to the protected agent. Only the
protected agent joins `agent-egress`; the gateway has no egress network and cannot bypass that
boundary. Adapt the protected agent port in the manifest if it does not listen on `8000`.

## Health and metrics

The gateway serves two internal endpoints without scanning or forwarding them:

```bash
curl --fail http://127.0.0.1:8787/healthz
curl --fail http://127.0.0.1:8787/metrics
```

`/healthz` returns HTTP 200 while accepting work and HTTP 503 during graceful shutdown. `/metrics`
is Prometheus text with metadata-only counters and timings for decisions, blocks, sanitizations,
failures, scanner latency, upstream latency, in-flight requests, and uptime. No payloads, headers,
secrets, wallet addresses, endpoint paths, or request IDs are emitted as metric values or labels.
The metrics have no variable labels, so their cardinality is bounded.

## systemd

Install from a reviewed release under `/opt/warden/current`, create a dedicated service account,
and protect the persistent state before enabling the unit:

```bash
sudo useradd --system --home-dir /var/lib/warden-gateway --shell /usr/sbin/nologin warden-gateway
sudo install -d -o warden-gateway -g warden-gateway -m 0700 /var/lib/warden-gateway
sudo chmod 0700 /var/lib/warden-gateway
sudo cp deploy/systemd/warden-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now warden-gateway.service
sudo systemctl status warden-gateway.service
```

The checked-in unit assumes the protected agent listens at `127.0.0.1:8000`. It starts the gateway
in local mode at `127.0.0.1:8787`, grants write access only to `/var/lib/warden-gateway`, and uses a
30-second stop timeout. Put nginx or another reviewed local reverse proxy in front when remote
clients need access; do not change the gateway listener to a public interface.

## Upgrade and rollback

Before an upgrade, keep the previous reviewed release directory, install dependencies into the new
release virtual environment, run the SDK and deployment tests, and then atomically update
`/opt/warden/current`. Restart and verify both internal endpoints:

```bash
sudo systemctl restart warden-gateway.service
curl --fail http://127.0.0.1:8787/healthz
curl --fail http://127.0.0.1:8787/metrics
```

Rollback by restoring `/opt/warden/current` to the previous reviewed release and restarting the
unit. Preserve `/var/lib/warden-gateway`; replacing it rotates the signing identity and resets local
scanner state.

## Local smoke test

Start a disposable upstream on port `8000`, launch the gateway with the Docker or systemd command,
and send a known-safe UTF-8 body through `127.0.0.1:8787`. Confirm the upstream receives it. Then
send a known blocked payload and confirm the client receives HTTP 403 while the upstream records no
request. Stop the gateway during a slow allowed request and confirm that request completes, new
requests receive HTTP 503, and `/healthz` reports HTTP 503 until shutdown completes.
