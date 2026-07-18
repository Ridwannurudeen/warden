# Dependency update policy

Warden accepts dependency, lockfile, GitHub Action, and build-tool updates only through a reviewed
pull request. Dependency update pull requests must not be auto-merged. The reviewer checks the
upstream release notes, provenance, compatibility, security impact, and whether the proposed version
still preserves Warden's frozen API and evidence contracts.

## Python lock refresh

Regenerate the Linux/Python 3.11 lock from the declared root and SDK requirements:

`uv pip compile pyproject.toml sdk/python/pyproject.toml --extra dev --extra langchain --extra llamaindex --generate-hashes --python-platform x86_64-unknown-linux-gnu --python-version 3.11 -o requirements.lock`

Review every version and hash change. Then run:

- `python -m pip install --require-hashes -r requirements.lock`
- `python -m pip_audit --require-hashes -r requirements.lock --disable-pip`
- `python -m pytest -q`
- `python -m build --no-isolation`
- `python -m twine check dist/*`

## TypeScript SDK lock refresh

Update dependencies only in `sdk/ts`, commit the resulting `package-lock.json`, and run:

- `npm ci`
- `npm audit --audit-level=high`
- `npm test`
- `npm run build`
- `npm pack --dry-run`

## CI and scanner tools

GitHub Actions remain pinned to verified 40-character commit SHAs. TruffleHog remains pinned to an
exact release and SHA-256 archive digest. A tool update must verify the upstream tag or release,
record the new immutable value in the workflow contract test, and pass the full-history secret scan.
Mutable tags are not accepted.

## Review, cadence, and rollback

Security advisories are reviewed when received. Routine dependency updates are reviewed at least
monthly and before a production release. A pull request must include the relevant upstream release
notes, the commands and results above, and any migration or compatibility impact.

If a gate fails or production behavior regresses, do not merge or deploy the update. Rollback means
reverting the dependency and lockfile changes together to the last tested commit, rerunning the same
gates, and deploying only after separate user approval.
