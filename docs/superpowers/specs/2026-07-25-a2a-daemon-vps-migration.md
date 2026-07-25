# A2A Daemon → VPS Migration Runbook

**Date:** 2026-07-25
**Goal:** move the `okx-a2a` daemon off the Windows laptop onto the VPS so Warden's OKX.AI
`onlineStatus` no longer depends on a personal machine being awake.
**Status:** plan only — **nothing in here has been executed.** Every mutating step is user-gated.

---

## 0. Why this migration exists

[VERIFIED 2026-07-25] Warden's two marketplace surfaces run on **different machines**:

| Surface | Runs on | Always up? |
| --- | --- | --- |
| A2MCP paid endpoints `/scan`, `/audit` | VPS `75.119.153.252` (`warden.gudman.xyz`, flat layout `/opt/warden`, app on `127.0.0.1:8031`) | yes |
| **A2A presence — the online/offline badge** | **the Windows laptop** | **no** |

The badge is driven by a heartbeat, not by endpoint health. [VERIFIED — `listener.log`] the local daemon
runs `onchainos agent heartbeat --chain-index 196` **every 60 seconds**. On 2026-07-24 the daemon died at
22:06 UTC; the badge flipped to `OFFLINE` while `/scan` and `/audit` kept returning correct
`402 + PAYMENT-REQUIRED` the entire time. Agent Frisk (#5087) was `online` with byte-identical 402
behaviour, which is what proves the badge ignores the HTTP surface.

[VERIFIED — `deploy/DEPLOY.md:10`] the VPS has **no authenticated `onchainos` CLI** today
("none of which exist today").

[INFERENCE — not verified] because `onlineStatus` is heartbeat-driven, **every** OKX.AI agent needs a live
daemon somewhere for the badge, regardless of whether it lists A2A services. Dropping Warden's A2A service
would therefore **not** remove this dependency. Treat as a working assumption; confirm before relying on it.

### Interim mitigation already in place (2026-07-25)

1. `okx-a2a-daemon.vbs` in the Windows Startup folder — instant start at logon, hidden.
2. Scheduled task **"OKX A2A Daemon Watchdog"**, every 5 min, run-as `gudma`.
   Proven by force-kill: unattended recovery in ~5 min. **Worst case exposure ≈ 5 minutes**, and only while
   the user is logged in.

This runbook replaces that with something that does not depend on the laptop at all.

---

## 1. Hard constraints

### C1. Never run two daemons on one identity
The XMTP state is per-installation SQLite: [VERIFIED]
`~/.okx-agent-task/xmtp/<installation>-production.db3` (+ `-shm`, `-wal`). Running the laptop daemon and a
VPS daemon against the same agent identity at the same time risks forked or corrupted message state.
**The local daemon must be fully stopped, and its watchdog disabled, before the VPS daemon starts.**

### C2. The daemon is not a heartbeat pinger — it answers tasks
[VERIFIED] the local `listener.log` records **445 `AI session done` entries**, dispatching to the Claude CLI
(`provider=claude`). If the VPS daemon runs **without** a working AI provider, Warden will go online and then
**accept A2A tasks it cannot answer** — strictly worse than being offline, because it damages a 5.0/100%
reputation with real buyers. **Provider readiness is a blocking prerequisite, not a follow-up.**

### C3. The VPS is shared
[VERIFIED — `deploy/DEPLOY.md:14`] "the host runs other live projects". A bad unit, a runaway process, or a
port collision is collateral damage to unrelated production. Every unit gets resource bounds and a rollback.

### C4. Credentials move to a shared host
Putting `onchainos` wallet auth on the VPS widens the blast radius of a host compromise to the agent's
identity. This is a deliberate risk acceptance the user must make explicitly (§7).

### C5. Nothing here runs without approval
No SSH, no install, no unit enable, no identity refresh without an explicit go for that step. The migration
is reversible at every phase.

---

## 2. Facts needed before starting (fill these in; do not guess)

| Fact | Value | How to get it |
| --- | --- | --- |
| VPS host | `75.119.153.252` | [VERIFIED] |
| SSH access | `root@75.119.153.252` | [VERIFIED in deploy docs] |
| VPS OS + arch | ? | `uname -a; cat /etc/os-release` |
| VPS node version | ? | `node --version` — needs **≥ 22.14.0** |
| VPS npm present | ? | `npm --version` |
| VPS free RAM / disk | ? | `free -m; df -h /opt` — daemon + node + AI CLI is not small |
| Agent id | `3808` | [VERIFIED] |
| Owner wallet | `0xf4c9fa07f3bb852547fdc4df7c1d9fd9991cfa51` | [VERIFIED] |
| Communication address | `0xBdaEF4FC4e2cf0173d0096B5487137fb808AaED9` | [VERIFIED] |
| Agents on this identity | **3** (`agentCount: 3, activeClients: 3`) | [VERIFIED] — migration affects **all three**, not just Warden |
| AI provider strategy on VPS | ? | §4 decision |

**Note the agent count.** The daemon serves three agents. Migrating moves all of them; any agent left
behind loses its badge.

---

## 2b. Phase 1 preflight results — BLOCKER FOUND (executed read-only, 2026-07-25)

The preflight ran and **stopped Phase 1 at step 4.** Nothing on the VPS was modified: no user created, no
package installed, no daemon started, no credential entered.

**Host is fine.** Ubuntu 24.04.3 LTS, kernel 6.8, x86_64, 8 CPUs, 24 GB RAM (~9 GB available), 888 GB free
on `/`. **node v23.11.1** and **npm 10.9.2** both clear the ≥ 22.14.0 requirement, so no node work is needed.

**`deploy/DEPLOY.md:10` is stale.** It says an authenticated `onchainos` CLI does not exist on the VPS. Both
CLIs are in fact already installed: `onchainos` **4.2.4** at `/usr/local/bin/onchainos` (newer than the
laptop's 4.1.0) and `okx-a2a` **0.1.9** at `/usr/bin/okx-a2a` (the laptop is on 0.1.10). `/root/.okx-agent-task`
exists with only a `sqlite/` subdirectory — no `xmtp/` state, so no agent communication identity has ever been
established there. `okx-a2a daemon status` → **`stopped`**, and no `okx-a2a`/`a2a-node`/`onchainos` process is
running, so constraint **C1 is not currently violated**.

**The blocker: the VPS is authenticated to a different wallet than the one that owns Warden.**

| Host | Wallet | Agents | Online |
| --- | --- | --- | --- |
| Laptop | `0xf4c9…cfa51` | **#3808 Warden** (ASP), #6961 Tilla (ASP), #4844 Gudman (User) | all `1` |
| VPS | `0x43ea…af55` | #8333 Tilla Studio (ASP, *listing under review*), #8345 Tilla Demo Buyer (User) | both `2` |

These are two separate OKX accounts. Warden's presence cannot be served from the VPS until the wallet that
owns `#3808` is authenticated there, and that is a credential action for the user — not something to be
automated.

**Two consequences the plan did not anticipate:**

1. **The laptop daemon carries three production agents, not one.** Migrating Warden moves Tilla `#6961` and
   Gudman `#4844` too, since they share the same wallet and the same daemon. Any partial migration splits one
   wallet across two hosts.
2. **The VPS already serves another account's agents.** Adding a second wallet there must not disturb the
   existing Tilla Studio setup, especially while `#8333` is under listing review. `onchainos` groups agents by
   `accountName`, which suggests multiple wallets are supported on one host, but that is **unverified** and
   must be confirmed before touching the VPS auth state.

**Also worth noting, unrelated to this migration:** both VPS-account agents are offline (`onlineStatus: 2`),
for the same root cause — no daemon is running anywhere for that wallet.

**Decision required before Phase 1 can continue** (see §7 / C4): whether to authenticate Warden's wallet
alongside the existing one on the shared host, and if so, who performs that credential step.

## 3. Phase 1 — Prepare the VPS (no cutover, fully reversible)

Nothing in this phase touches the running laptop daemon or the live listing.

1. **Preflight the host** — capture `uname -a`, `/etc/os-release`, `node --version`, `npm --version`,
   `free -m`, `df -h /opt`. Abort if node < 22.14.0 (install a supported node first; do **not** upgrade a
   shared host's system node without checking what else depends on it).
2. **Create a dedicated service account** — `warden-a2a`, no login shell, own home. Do **not** run the
   daemon as `root` on a shared host.
3. **Install the CLI** as that user: `npm install -g @okxweb3/a2a-node@latest` (current laptop version is
   `0.1.10`). Record the installed version.
4. **Install + authenticate `onchainos`** on the VPS as that user. This is the piece
   `deploy/DEPLOY.md:10` says does not exist. It needs the wallet credentials — see C4 and §7.
5. **Verify read-only** before any write: an `onchainos` agent read that returns agent `3808` proves auth
   works without mutating anything.

**Rollback:** delete the service account and the global npm package. The laptop daemon has not been touched,
so the listing is unaffected.

---

## 4. Phase 2 — AI provider on the VPS (blocking; see C2)

Decide the strategy **before** cutover:

- **Option A — full parity.** Install and authenticate the Claude CLI on the VPS so A2A tasks are answered
  there exactly as they are today. Highest fidelity, needs credentials on a shared host, and the VPS must
  have the resources for AI sessions.
- **Option B — presence only (recommended first step).** Run the daemon on the VPS for the heartbeat, and
  deliberately **do not list A2A services**, so no task can arrive that needs an AI answer. This restores
  a permanently-online badge with far less risk. Requires delisting/pausing the
  "Escrow Payload Security Scan" A2A service, which is a listing change and therefore user-gated.
- **Option C — split.** VPS daemon for presence; keep A2A task handling on the laptop. **Rejected** — it
  violates C1 (two daemons, one identity).

[DECISION REQUIRED] Option A or B. Do not proceed to cutover without one chosen and its prerequisite met.
If A: prove an AI session completes end to end on the VPS **before** cutover.

---

## 5. Phase 3 — Identity strategy

Two ways to give the VPS daemon Warden's communication identity:

- **Strategy 1 — refresh in place (preferred).** Start the daemon on the VPS and run its own
  `agent refresh`, letting it establish a fresh XMTP installation for the same agent. No secrets copied
  between machines. **Unverified:** whether OKX/XMTP accepts a new installation for an existing
  `communicationAddress` without extra steps. **Test this on a non-critical agent first** — the identity
  serves three agents, so pick one that is not Warden.
- **Strategy 2 — copy the SQLite state.** `scp` the `~/.okx-agent-task/xmtp/*.db3` (+ `-shm`, `-wal`) files.
  Preserves message history, but copies identity material over the wire and risks a half-copied WAL.
  If used: stop the laptop daemon **first** so the WAL is quiesced, copy all three files per installation,
  and never leave both copies running (C1).

[DECISION REQUIRED] Strategy 1 or 2. Strategy 1 is preferred; validate it on a non-Warden agent.

---

## 6. Phase 4 — Cutover (the only step that can take the listing offline)

Do this in a window where a few minutes of `OFFLINE` is acceptable — **not** inside the last hours before a
submission deadline.

1. **Disable the laptop watchdog first** (otherwise it resurrects the local daemon and breaks C1):
   - delete the scheduled task **"OKX A2A Daemon Watchdog"**
   - remove `okx-a2a-daemon.vbs` from the Startup folder
2. **Stop the laptop daemon** and confirm it is down.
3. **Start the VPS daemon** as `warden-a2a`; run the readiness flow in the documented order:
   daemon start → `switch-runtime --json` → `agent refresh --json` → `setup --json`. All must return `ok`.
4. **Confirm the heartbeat is now coming from the VPS** — `heartbeat sent` lines in the VPS log, and
   `lastOnlineTime` on agent `3808` advancing while the laptop daemon stays stopped. This is the
   single most important verification in the whole runbook.
5. **Confirm `onlineStatus: 1`** for all three agents.

**Rollback (fast, ~2 min):** stop the VPS daemon, restore the Startup `.vbs` and the watchdog task, start
the laptop daemon, confirm `onlineStatus: 1`. Keep the `.vbs` content in this repo or a note so it can be
recreated from scratch.

---

## 7. Phase 5 — Make it survive reboots, and bound it

1. **systemd unit** `okx-a2a-daemon.service` — `User=warden-a2a`, `Restart=always`,
   `RestartSec=10`, `WantedBy=multi-user.target`, plus the hardening already used by the repo's other units
   (see `deploy/systemd/warden-gateway.service` as the in-repo template: `NoNewPrivileges`,
   `ProtectSystem`, `PrivateTmp`, `StateDirectory` with `0700`). Add `MemoryMax=` / `CPUQuota=` — C3.
2. **`systemctl enable`** so it survives reboot. This is what finally removes the laptop dependency.
3. **Log rotation** — the laptop `listener.log` grows with every AI session and heartbeat;
   the log directory already holds ~26 MB. Rotate on the VPS or it will fill a shared disk.
4. **Independent monitoring** — see §8; the current alerting path is broken.

---

## 8. Known blocker: you would not be told if this fails again

[VERIFIED — `listener.log`] `onchainos agent user-notify` fails with
**"An Application Control policy has blocked this file" (os error 4551)** — Windows Smart App Control blocks
a helper the notify path spawns (`next-action` still works).

So the built-in alerting cannot reach the user. Whatever runs on the VPS, add an **external** check that
does not depend on OKX's notify path: poll `onlineStatus` for agents `3808` (+ the other two) on a schedule
and alert through a channel that is known to work. Without this, the next outage is again discovered by
accident.

---

## 9. Post-migration cleanup

- Remove the laptop Startup `.vbs` and the watchdog task (already done at cutover step 1 — verify they are
  still absent).
- If `okx-a2a daemon autostart install` is ever run on Windows with elevation, make sure the Startup `.vbs`
  is **not** also present, or both will fire.
- Update the memory note `warden-okx-online-status.md` to record that presence now lives on the VPS.
- Update `deploy/DEPLOY.md:10`, which currently states the VPS has no authenticated `onchainos` CLI.

---

## 10. Deployment gap found while writing this (separate from the migration)

[VERIFIED] `deploy/TRUST-LAYER-DEPLOY.md` is the current procedure (per `deploy/DEPLOY.md:7`), and its
public-verification block **Step 5b** checks only `/scan` and `/audit` → 402. It predates:

- **`POST`/`GET /harden`** — the paid route is in source and in `deploy/nginx-warden.conf:53`, but
  **404s live** (verified by probing `https://warden.gudman.xyz/harden`), i.e. not deployed.
- **`GET /apa/hardening/{pack_id}`** — the public signed-pack lookup.
- **`/lineage`** — the new audit-evidence-lineage page. No nginx change needed (the catch-all
  `try_files $uri $uri.html` at `deploy/nginx-warden.conf:177` serves it), but it is not deployed either.

**Before or alongside the migration, `TRUST-LAYER-DEPLOY.md` Step 5b needs extending** to assert
`/harden` → 402 on both GET and POST, `/apa/hardening/{unknown}` → 404, and `/lineage` → 200. Shipping the
app without updating that verification block means the deploy "passes" while the new paid route is dead.

---

## 11. Execution order (recommended)

1. Extend `TRUST-LAYER-DEPLOY.md` Step 5b for `/harden`, `/apa/hardening/…`, `/lineage` — **repo-only, safe
   to do now.**
2. Phase 1 (VPS prep) — reversible, no listing impact.
3. Phase 2 decision (A or B) and prove it.
4. Phase 3 decision (Strategy 1 or 2), validated on a non-Warden agent.
5. Phase 4 cutover — **outside the submission window.**
6. Phase 5 hardening + §8 external monitoring.
7. §9 cleanup.

**Explicitly out of scope until the user says otherwise:** deploying the app itself, changing the listing,
delisting the A2A service, moving wallet credentials, and any SSH session.
