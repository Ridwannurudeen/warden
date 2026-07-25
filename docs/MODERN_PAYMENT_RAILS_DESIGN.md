# Modern payment rails: verified design and activation gates

**Status:** design complete; implementation intentionally blocked until the supported client,
server, and facilitator surfaces are verified together.

Warden's production rail remains unchanged: x402 v2 `exact`, `eip155:196`, 0.1 USDT
(`100000` atomic units), and one `accepts` entry on each paid route. This document does not authorize
a dependency update, deployment, authenticated OKX request, or payment.

## Verified 2026-07-24

- The repository pins `okxweb3-app-x402[fastapi,evm]==0.1.0`. The installed distribution is 0.1.0
  and its `x402` module reports 2.5.0.
- The installed package has 67 Python files. Its only payment-scheme string literals are `exact` and
  `aggr_deferred`. `AggrDeferredEvmScheme` is server-side only. There is no `upto`, `period`,
  `permit2_subscription`, voucher, top-up, or payment-channel implementation in that package.
- The official 0.1.1 wheel has the same 67-file layout and the same two scheme literals. A static
  0.1.0-to-0.1.1 source comparison found changes in twelve existing modules but no modern-rail
  module. The wheel was inspected without installation and then removed.
- OKX's Python x402 reference documents `exact` and server-side `aggr_deferred` for
  `okxweb3-app-x402`. The wider SDK matrix marks Python `upto` and `period` as coming soon.
- Current OKX documentation describes Python `session` support in separate `mpp` and `mpp_evm`
  packages. That surface is seller-side; `EvmMethod.create_credential` is documented as
  `NotImplementedError`, so the documented Python stack does not prove buyer-to-seller
  interoperability.
- The current OKX documentation does publish MPP session operations. This corrects the older handoff
  claim that no session endpoints exist. It does not make those operations available through
  Warden's installed x402 package.
- `scripts/monitor_readiness.py` rejects a `/scan` challenge unless it contains exactly one pinned
  payment option. Adding another option to the existing route would break readiness monitoring.
- `load_payment_rail()` rejects every divergent or unknown `WARDEN_PAYMENT_*` value. The existing
  rejected-override tests, including `upto`, remain required.

Primary references:

- [OKX Python SDK reference](https://web3.okx.com/ru/onchainos/dev-docs/payments/sdk-python)
- [OKX payment-method coverage](https://web3.okx.com/de/onchainos/dev-docs/payments/sdk-overview)
- [OKX one-time HTTP API](https://web3.okx.com/nb/onchainos/dev-docs/payments/api-http-onetime)
- [PyPI release history](https://pypi.org/project/okxweb3-app-x402/)

## Additive design

The future implementation must use a separate adapter selected by
`WARDEN_EXPERIMENTAL_MODERN_PAYMENTS`. The flag defaults to false. When false, no new dependency is
imported, the current route table and middleware objects are unchanged, and the serialized 402
challenge remains byte-identical.

The existing `/scan`, `/audit`, and `/harden` routes keep exactly one `exact` option. A modern rail
must first be proven on an additive route or a separate payment-router boundary at the same pinned
0.1 USDT amount. The original readiness monitor continues to inspect the original `/scan` challenge;
a separate monitor validates the experimental route. No second price tier is introduced.

The adapter must expose one internal result contract:

1. `challenge` when no valid credential is present;
2. `verified` with immutable payer, amount, asset, network, and settlement/session reference;
3. `rejected` for malformed, replayed, expired, underfunded, or unsupported credentials.

Only `verified` reaches the protected handler. Transport failure, schema drift, missing persistence,
or unsupported capability fails closed.

For sessions, replay protection and channel state must use a cross-process durable store. An
in-memory store is never production-capable. Voucher sequence, cumulative amount, expiry, channel
identity, payer, recipient, asset, and chain are verified atomically before the new state is
committed.

## Required verification before implementation

1. With user-provided OKX authentication, make one read-only authenticated `GET
   /api/v6/pay/x402/supported` request and retain the exact response for `eip155:196`. Do not infer
   live support from documentation examples.
2. Pin exact versions and hashes for `mpp`, `mpp_evm`, and any payment-router package. Read their
   source and confirm the seller, buyer, signer, store, receipt, and replay APIs actually exist in
   those versions.
3. Confirm an implemented buyer can create a credential that the Python seller verifies. The
   documented Python `NotImplementedError` must not be hidden behind a test stub.
4. Run a local multi-worker replay test against the proposed durable store: one voucher succeeds,
   concurrent duplicate presentation yields exactly one success, and restart preserves the spent
   sequence and cumulative amount.
5. Prove flag-off byte identity for route configuration, middleware ordering, 402 headers, response
   bodies, and the pinned readiness monitor.
6. Prove flag-on isolation: failures in the experimental adapter do not change the exact route and
   do not fall through to an unpaid handler.
7. Exercise expiry, top-up, close, settlement, insufficient balance, chain mismatch, asset mismatch,
   recipient mismatch, out-of-order voucher, duplicate voucher, and store-unavailable cases.
8. Re-run the full Warden gate and add an independent readiness monitor for the additive route.
9. Obtain explicit user approval for the dependency and lockfile change before implementation, and
   separate approval for any deployment or authenticated production check.

## Rollback

Disable `WARDEN_EXPERIMENTAL_MODERN_PAYMENTS`, remove the additive router from service configuration,
and retain the session store read-only for reconciliation. The original `exact` routes, source
configuration, and monitor require no rollback because the design does not modify them.
