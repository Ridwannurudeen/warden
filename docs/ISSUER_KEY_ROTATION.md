# APA Issuer-Key Rotation

This is the canonical source procedure for rotating Warden's APA issuer key. It is an operator runbook, not
evidence that a live rotation has happened. Run it only after deployment approval and from the reviewed
release. The invariant is simple: the original database remains untouched while a candidate copy is probed
and re-signed, and no candidate file is promoted unless every initially eligible attestation was updated with
zero skips and verifies under the new current issuer key.

Do not print, log, or pass the issuer seed as a command-line argument. The new seed belongs only in the
root-owned, group-readable application environment file described below. Command output contains counts, not
key material.

## 1. Prepare rotation material

Prepare these regular, non-symlink files on the same filesystem as their final destinations:

- `/opt/warden/.env.rotation`, owned by `root:warden` with mode `0640`, is the complete application
  environment with the new `WARDEN_ISSUER_KEY`, a unique `WARDEN_ISSUER_KID`, and the canonical
  `WARDEN_ISSUER_HISTORY` path.
- `/opt/warden/index.env.rotation`, owned by `root:warden` with mode `0640`, contains only the unchanged
  badge-verification secret, the new public `WARDEN_ISSUER_PUBLIC_KEY`, and the canonical public-history path.
  It must not contain `WARDEN_ISSUER_KEY`.
- `/opt/warden/issuer-history.json.rotation`, owned by `root:warden` with mode `0640`, contains only public
  retired keys. Add the former current public key with a finite `not_after` cutoff covering the records that
  will be migrated. Never place an old private seed in this file or any long-term rotation material.

Validate file ownership, modes, absence of symlinks, unique key IDs, and that the public key in the index
environment is derived from the private seed without displaying either value. Stop if any validation fails.

## 2. Quiesce and back up

Stop the API and both writers before copying state: `warden.service`, `warden-apa-reprobe.timer` and its
service, plus the Safety Index timer and service. Confirm none is active. Create a root-only backup directory
on `/opt/warden`, then preserve the current application environment, index environment, issuer history,
Safety Index link target, and `/opt/warden/data/protection.db`. Keep this backup until post-rotation checks and
the one-hour attestation grace window have passed.

Do not continue unless the backup database is a regular file, non-empty, and opens read-only with SQLite.
Because all writers are stopped, this backup is also the rollback boundary.

## 3. Prove the rotation with an ephemeral candidate

Create the candidate directory as `warden:warden` with mode `0700`, but do not create `candidate.db`. The
rotation script refuses an existing candidate, copies the quiesced source with SQLite's read-only backup API,
and uses a private staging name on the same filesystem. In `--dry-run` mode it performs the complete re-probe
and signature gate, then removes the ephemeral candidate. It never points the application or a timer at that
copy.

```bash
app=/opt/warden
source_db=/opt/warden/data/protection.db
candidate_db=/opt/warden/data/.issuer-rotation/candidate.db
candidate_app_env=/opt/warden/.env.rotation
candidate_history=/opt/warden/issuer-history.json.rotation
install -d -o warden -g warden -m 0700 /opt/warden/data/.issuer-rotation
test ! -e "$candidate_db"
test ! -L "$candidate_db"
```

The candidate directory must be on the same filesystem as `protection.db` so both candidate publication and
final operator promotion are atomic. Stop if the source has a stale SQLite journal, WAL, or shared-memory
sidecar. Run the full dry-run as the unprivileged `warden` user:

```bash
runuser -u warden -- env -i \
  HOME=/opt/warden \
  PATH="$app/.venv/bin:/usr/local/bin:/usr/bin:/bin" \
  APP="$app" \
  APP_ENV="$candidate_app_env" \
  SOURCE_DB="$source_db" \
  CANDIDATE_HISTORY="$candidate_history" \
  bash -c 'set -euo pipefail
    set -a
    . "$APP_ENV"
    set +a
    export WARDEN_ISSUER_HISTORY="$CANDIDATE_HISTORY"
    cd "$APP"
    exec .venv/bin/python scripts/rotate_issuer_key.py \
      --source-db "$SOURCE_DB" \
      --dry-run'
```

Successful output contains only mode and attestation counts. Confirm no database or SQLite sidecar was left
in `.issuer-rotation`. A non-zero exit means the key material, history, source database, endpoint probes, or
complete-current-issuer gate failed; investigate before continuing.

## 4. Build the verified database candidate

Run the same orchestrator without `--dry-run`. It repeats every proof against a fresh staging copy and exposes
`candidate.db` only after the complete-current-issuer gate passes:

```bash
runuser -u warden -- env -i \
  HOME=/opt/warden \
  PATH="$app/.venv/bin:/usr/local/bin:/usr/bin:/bin" \
  APP="$app" \
  APP_ENV="$candidate_app_env" \
  SOURCE_DB="$source_db" \
  CANDIDATE_DB="$candidate_db" \
  CANDIDATE_HISTORY="$candidate_history" \
  bash -c 'set -euo pipefail
    set -a
    . "$APP_ENV"
    set +a
    export WARDEN_ISSUER_HISTORY="$CANDIDATE_HISTORY"
    cd "$APP"
    exec .venv/bin/python scripts/rotate_issuer_key.py \
      --source-db "$SOURCE_DB" \
      --candidate-db "$CANDIDATE_DB"'
```

The orchestrator requires all initially eligible records to verify through the public retired-key history
before it invokes `reprobe_protections.py --require-complete-current-issuer` internally. It then reloads every
snapshot ID, verifies each signature directly against the new current issuer, verifies the signed log head,
and proves byte-for-byte that both source database and history file stayed unchanged. An unreachable endpoint
is recorded honestly as `stale`; a bad proof is `invalid`; either candidate record is still signed by the new
current key. A corrupt record, missing retired key, concurrent source change, skipped update, or failed write
exits non-zero and leaves no publishable candidate. Do not promote after a non-zero exit.

## 5. Promote only after the gate passes

With all readers and writers still stopped, validate the candidate database read-only and confirm there are
no SQLite sidecars. Install same-filesystem temporary copies of the three candidate configuration files and
the candidate database beside their final paths. Promote the public history, index environment, application
environment, and database using atomic renames. Rebuild the Safety Index from the promoted database and
public-only index environment before restarting readers.

Keep an error trap active from the first rename through the post-start checks. The trap must restore all four
backed-up files and the previous Safety Index link before it restarts the old services. Never mix an old
database with the new signer or a new database with the old signer.

Start the API first and verify local `/health` plus `/.well-known/apa-issuer.json`. Then start the Safety Index
timer and the normal APA reprobe timer. Confirm the issuer document's first key matches the prepared public
index key, the timers are active, and the reprobe journal contains only the count summary. Mark the rotation
committed only after every check passes. Once the rollback window and one-hour attestation grace period have
passed, destroy the root-only backup of the old application environment. Retain only the retired public key
and its finite cutoff.

## Rollback

On any failure before commitment, keep every writer stopped. Restore the backed-up application environment,
index environment, public history, and protection database with same-filesystem temporary files and atomic
renames; restore the previous Safety Index link; validate the old issuer document; then restart the API and
timers. Do not delete the failed candidate or backup until the cause is understood, but keep both inaccessible
to non-operators.

After commitment, rollback is still the full four-file operation. Restoring only the seed or only the
database creates signatures that the active issuer configuration cannot validate.
