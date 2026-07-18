# Warden Gateway

Build and run the fail-closed local gateway on the same Docker network as the protected agent:

```bash
docker build -f deploy/Dockerfile.gateway -t warden-gateway . && docker run --rm --network agent-stack -p 8787:8787 -v warden-gateway-state:/var/lib/warden-gateway warden-gateway --upstream http://my-agent:8000 --mode local
```

The command builds from this reviewed checkout; it does not rely on an unpublished image or
package. The named volume retains only the local guard key and scan-count state. Signed verdict
receipts are written to standard output without payloads or secrets.

Hosted mode uses the protected `/scan` path and fails closed. The SDK does not settle x402
payments, so do not point hosted mode at the public paid route without a separate payment-aware
transport.
