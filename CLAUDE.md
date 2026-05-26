# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

The parent monorepo's `../CLAUDE.md` already covers the high-level story (architecture, wired sources, decision rules, deployment, skills). This file is the module-local counterpart: dev commands and conventions specific to working *inside* `reel-vex/`.

## Commands

```bash
go build -o reel-vex ./cmd/server          # build
go test ./...                              # unit + package tests (no network)
go test -tags integration ./test/integration/   # builds binary, seeds DB, hits HTTP
go test ./pkg/source/ubuntuvex/...         # one package
go test -run TestExpand_PreservesDistro ./pkg/resolver/   # one test
```

CLI subcommands (after `go build`):
```bash
./reel-vex -config config.yaml -db vex.db ingest        # one-shot ingest
./reel-vex -config config.yaml -db vex.db serve         # HTTP API + scheduled ingest
./reel-vex -db vex.db query CVE-2024-6387               # local DB lookup
./reel-vex -db vex.db stats                              # row counts
```

`docs/architecture.md` (pipeline + layout), `docs/data-model.md` (schema), `docs/api.md` (HTTP reference) are the longer-form docs — keep them in sync with code changes.

## Adapter framework

Every VEX feed is an `Adapter` (`pkg/source/adapter.go`): `Discover` → `Sync(since, emit)`. The orchestrator (`pkg/ingest/ingest.go`) is format-agnostic; it tags emitted statements with the adapter's `Vendor()` and `SourceFormat()` before writing.

**Adding a new adapter type** (concrete steps):
1. New package under `pkg/source/<name>/` exporting a `Type` constant and a `New(cfg AdapterConfig) (source.Adapter, error)` factory.
2. Register it in `cmd/server/main.go` `registerAdapters()`.
3. Add an entry to `config.yaml` with the matching `type:` field. **Adapters not in `config.yaml` are dormant** — registration alone doesn't instantiate them.
4. Add a fixture in `testdata/` and an httptest-backed adapter test (no network in tests).

**OVAL adapters delegate to `getreeldev/oval-to-vex`** (sibling repo). New OVAL vendor = new `translator.FromXOVAL()` upstream + new wrapper adapter here.

**Adapter ID rules**: `ID()` is unique across config (used as watermark key in `adapter_state`). `Vendor()` is the canonical vendor string written onto statements — multiple adapters under one vendor share it (e.g. all Red Hat OVAL streams return `"redhat"`); provenance is preserved via `SourceFormat()`.

## Database & migrations

SQLite via `modernc.org/sqlite` (pure-Go, no cgo). Migrations in `pkg/db/migrations.go` are auto-applied on every binary boot, tracked by `schema_version`. **Forward-only**; rollback = restore from a pre-upgrade backup. `statements` PK is `(vendor, cve, product_id, source_format)` — same vendor+CVE+product can legitimately appear under both CSAF and OVAL.

`/v1/stats` is served from a cached struct refreshed at the end of each ingest cycle (full-table COUNTs are 30–60s on the prod-size DB). **Tests that mutate the DB and re-read stats must call `database.RefreshStats()` between mutation and read.**

## Resolver (`pkg/resolver/`)

Three expansion rules at query time: `direct`, `via_alias` (PURL `?repository_id=` → CPE), `via_cpe_prefix` (CPE 2.2 5-part prefix, Red Hat SECDATA-1220). Each match carries a `match_reason`; stronger reasons win when multiple rules produce the same candidate.

`?distro=` is **identity-bearing for deb-shaped PURLs** (focal openssl ≠ noble openssl) and is preserved on `base_id`. For RPM PURLs, scanner-emitted `?distro=redhat-X.Y` is stripped to also produce a bare candidate (v0.4.3 — Trivy/syft fix). `arch`, `epoch`, `repository_id` are always stripped from the base.

## API conventions

All VEX-statement-emitting endpoints (`/v1/statements`, `/v1/analyze`) return **OpenVEX 0.2.0**. Provenance and match reasoning ride in `status_notes` as `key=value; key=value` (`source_format=`, `match_reason=`) — don't invent custom OpenVEX fields. `/v1/analyze` returns CycloneDX in place (annotated SBOM, with BOM-Link refs in `affects[].ref` for Trivy `--vex` consumption).

User-supplied OpenVEX merging lives in `pkg/uservex/` — in-memory only, never persisted, never logged. User overrides take precedence over vendor statements.

`-sbom-max-mb` (default 5) caps body size for both SBOM-accepting endpoints; the constructor stays stable and tests use `api.Server.SetSBOMMaxBytes(...)`.

## Testing conventions

- **No network** in unit tests. Each adapter has an `httptest.Server` serving committed fixtures from `testdata/`.
- **Integration tests** (`test/integration/`) build the binary, seed a temp DB, and hit the HTTP API end-to-end. Gated behind `-tags integration` so they don't run in default `go test ./...`.
- New adapter or endpoint = both a unit test (close to the code) and an integration test (full HTTP path).
- **Live smoke** (opt-in, network): `pkg/source/ranchervex.TestSmoke_LiveFeed` fetches the real Rancher feed and asserts the adapter's invariants against live data — catches upstream restructuring a committed fixture can't. Gated behind `REEL_VEX_SMOKE=1`; skipped in default `go test ./...`. Run: `REEL_VEX_SMOKE=1 go test -run TestSmoke -v ./pkg/source/ranchervex/`.

## Per-source quirks: where do fixes live?

(From the parent CLAUDE.md, repeated here because adapter authors hit this constantly.)

1. Spec-compliance deficiency in the feed → core code (e.g. permissive fallback in `pkg/csaf/extract_permissive.go`).
2. Semantic gap only another source can fill → new adapter / new feed (e.g. RH OVAL filling RH CSAF EUS gap).
3. Vendor data error → `config.yaml` or a small data file, not code.
4. Cross-vendor pattern emerging → implement once here, promote to library on second hit.

## Git author

Inherited from parent: commits use `Reel Bot <bot@getreel.dev>`, no Claude footer.
