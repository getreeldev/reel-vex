# reel-vex — notes for coding agents

reel-vex is the open-source VEX hub behind `vex.getreel.dev`: it ingests vendor VEX and
advisory feeds into Postgres, translates between identifier schemes, and answers queries
in OpenVEX 0.2.0. `README.md` is the user's view, `docs/architecture.md` how ingest and
removal work, `docs/data-model.md` the schema, `docs/api.md` the HTTP contract. Read the
one that matches the change before making it.

**This repository is public.** It says what reel-vex is and does — code, `docs/`,
`CHANGELOG.md`, `README.md`. Plans, design discussions, deployment details (hosts,
addresses, topology) and the history of how a decision was reached do not belong here, in
a file, a commit message or a code comment. Grep a diff for host names and addresses
before pushing.

## Commands

```bash
go build ./cmd/server
go vet ./... && go vet -tags integration ./...
gofmt -l .
go test -count=1 ./...                                   # no network, no database
export REEL_VEX_TEST_PG_DSN='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable'
go test -count=1 -p 1 ./pkg/db/postgres/                 # TestPG
go test -tags integration -count=1 -p 1 ./test/...       # integration + acceptance
```

The Postgres suites skip without `REEL_VEX_TEST_PG_DSN` and still print `ok` (they fail
under `CI=true`). They truncate the same tables, so run them one package at a time (`-p 1`)
against a throwaway database, e.g. `docker run --rm -d -e POSTGRES_PASSWORD=postgres -p
5432:5432 postgres:16`. CI runs both on every push to every branch, against a
`postgres:16` service.

## Rules that shape changes

- **Mirror model.** The hub publishes whatever status the vendor stated — `not_affected`,
  `fixed`, `affected`, `under_investigation` — and the consumer decides. Never pre-filter
  to `not_affected`; `under_investigation` is a state consumers rely on.
- **The acceptance suite is the arbiter of answers.** `test/acceptance` serves trimmed real
  vendor documents, ingests them with the server binary (twice — day 2 exercises removal),
  and checks the exact answer to each query; every expected row cites where the vendor
  document says it. An expectation changes only with vendor evidence, never to match output.
- **Where a per-source fix lives:**
  1. The feed deviates from its spec → a permissive fallback in the core (`pkg/csaf` etc.).
  2. A gap only another source can fill → a new adapter or feed (Ubuntu OVAL exists because
     Canonical's OpenVEX names some packages differently).
  3. A vendor's data error → `config.yaml` or a small data file, not code.
  4. A pattern seen in two vendors → implement once; promote to a library on the second hit.
- **`config.yaml` is the source of truth** for which adapters run and from where. A feed URL
  that returns a Git-LFS pointer or an HTML page is wrong: fetch-test a URL before changing
  it. Adding an adapter type needs its `config.yaml` entries (else it is dormant); removing
  one needs them gone (else the server refuses to start on `unknown adapter type`).
- **Size schema changes against production-scale data.** The statements table is hundreds of
  millions of rows, ~95% of them Ubuntu OpenVEX. An index or migration that is cheap on a
  test database can roughly double the table; that is why the broad-mode covering index is
  built after ingest by `EnsureCoveringIndex` rather than in a migration. A release that
  changes which rows should exist (rows with no owning adapter are never removed) needs an
  empty database; say so under **Upgrade notes** in the changelog.
- **Timeouts on queries are server-side.** A cancelled Go context does not stop a Postgres
  query that is still scanning; use `SET LOCAL statement_timeout` inside a transaction (a
  plain `SET` rides the pooled connection back). A role-wide timeout would kill the ingest's
  long upserts.
- **Removal is guarded.** Every adapter's rows it no longer emits are removed after its run
  (whole-feed sweep, per-document replacement, CSAF withdrawal), under
  `-sweep-max-fraction`. A change to what an adapter emits, or to how much it emits in one
  run, is a change to removal: check the sweep's seen/owned counts, not only the upsert.
- **Every compatibility claim names the scanner it was checked with.** So far that is Trivy;
  Grype and other consumers are unverified.

## Feeds

Ten feeds over nine adapter types (`pkg/source/*`): Red Hat and SUSE CSAF, Canonical OpenVEX
(one tarball, all releases, re-reads only changed documents), Ubuntu, Debian, AlmaLinux and
Oracle OVAL (parsed by the sibling library `github.com/getreeldev/oval-to-vex`, imported as a
tagged module), Rancher VEX hub (product-scoped), Alpine secdb, Amazon Linux `updateinfo`.
Ubuntu deliberately has both OpenVEX and OVAL: neither is a superset of the other. Use the
`vendor-feed-audit` skill (`.claude/skills/`) before adding an adapter.

## Changelog and commits

- `CHANGELOG.md`: user-visible changes under `## [Unreleased]`, one line each, with
  **Breaking** and **Upgrade notes** where a reader must act. A release renames the heading
  to `## [X.Y.Z] — <title>` with a `*Released <date>*` line.
- Commits are authored and committed by `Reel Bot <bot@getreel.dev>`, with no AI-attribution
  trailer:
  `GIT_COMMITTER_NAME="Reel Bot" GIT_COMMITTER_EMAIL="bot@getreel.dev" git commit --author="Reel Bot <bot@getreel.dev>"`.
  A tag needs the same `GIT_COMMITTER_*` variables, or it carries the local git identity.
- A `v*` tag publishes the image to Docker Hub and a GitHub release. Never push a tag, or
  push to `main`, without the maintainer's explicit go.

## Working rules

- Do the change asked, at the size asked. Propose a wider cleanup; don't bundle it.
- Read the full diff before every commit: stale comments, leftovers, a missing log line.
- Before reporting that something is broken or absent, prove the check works: a pipeline's
  exit status is its last command's, and a CDN answers `curl` with compressed bytes.
- Describe code effort as complexity and risk, not time. Quote durations only for machine
  work (an ingest, a CI run).
