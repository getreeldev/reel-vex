# Changelog

All notable changes to reel-vex are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); reel-vex is pre-1.0 so minor bumps may carry breaking changes.

## [0.1.7] — Unreleased

### Added

- **Identifier translation layer.** The resolver now expands a queried product through vendor-published mapping files as well as the CPE-prefix rule. A scanner POSTing a PURL with `?repository_id=rhel-8-for-x86_64-appstream-rpms` gets matched against VEX statements keyed on `cpe:/a:redhat:enterprise_linux:8::appstream` — the CPE Red Hat actually publishes VEX under. Response `match_reason` gains a new value: `via_alias`. This is the change that moves reel-vex from pass-through cache to translation hub.
- **`pkg/aliases/` package** with a `Fetcher` interface, factory registry (`Register` / `New` / `BuildAll`), and Red Hat's `repository-to-cpe.json` as the first implementation. Fetchers run after adapters during the ingest cycle; failures log and continue so that a broken alias source doesn't block statement ingest.
- **New `product_aliases` table** (schema v2 migration, additive). Keyed `(vendor, source_ns, source_id, target_ns, target_id)` with bidirectional indexes. Exposes `BulkUpsertAliases`, `LookupAliases`, `AliasCount` on `db.DB`.
- **`pkg/resolver.Resolver`** struct composes all expansion rules — `direct`, `via_alias`, `via_cpe_prefix` — with a dedupe hierarchy where stronger reasons win. The pure `CPEPrefix` helper from Phase 1 stays in place and is now called by Resolver.
- **`config.yaml` gains an `aliases:` section** sibling to `adapters:`. Entries have `type`, `id` (associates with the vendor adapter), and optional `url` (defaults to the vendor's published URL).
- Regression test (`TestHandleResolve_AliasExpansion`) drives the full alias path end-to-end; integration test against an `httptest.Server` serving the committed `testdata/redhat-repository-to-cpe-sample.json` fixture verifies the fetcher.
- **`aliases` field on `/v1/stats`.** Total rows in `product_aliases`. Intended to surface on the website alongside vendors / CVEs / statements under the label **"Product mappings"**. Hosted-deployment operator note: expect ~12,000 to appear after the first alias-fetch cycle completes.

### Changed

- `ingest.Run` signature: now takes `(ctx, []source.Adapter, []aliases.Fetcher, *db.DB, Options)`. Pipeline orchestration runs adapters then fetchers.
- `api.Server` holds a `*resolver.Resolver`. `/v1/resolve` and `/v1/sbom` delegate product expansion to it. Previously these paths called a package-level helper; the instance-method form carries the DB dependency needed for alias lookups.

## [0.1.6] — Unreleased

### Added

- **Pluggable source adapter interface** (`pkg/source/`). Every vendor feed is now consumed through a common `Adapter` interface (`Discover` + `Sync`), with a small registry (`Register` / `New` / `BuildAll`) that routes config entries to factories by `type`. Foundation for OVAL (Phase 5) and future sources; third-party operators can register their own adapters without forking.
- **CSAF adapter** (`pkg/source/csafadapter/`). Existing CSAF orchestration (feed discovery, changes.csv walk, per-document fetch + parse) moved behind the adapter interface. `pkg/csaf/*` parsers stay unchanged. Tested end-to-end against an `httptest.Server` that serves the real Red Hat CVE-2024-0217 fixture.
- **`context.Context` plumbed through ingest.** Scheduled ingests now cancel cleanly on shutdown.

### Changed

- **`config.yaml` schema**: `providers:` → `adapters:` with a required `type:` field per entry. Old schema no longer parsed. Hosted deployments must update their config file when they roll the new binary. Current config:
  ```yaml
  adapters:
    - type: csaf
      id: redhat
      name: Red Hat
      url: https://security.access.redhat.com/data/csaf/v2/provider-metadata.json
  ```
- **`-limit` now counts statements, not documents.** Consistent unit across every adapter type (CSAF emits per-CVE, OVAL emits per-tarball, etc.; statements are the only shared primitive). Production runs `-limit 0` so this is a dev-convenience change only.
- **`ingest.Run` signature**: now takes `(ctx, []source.Adapter, *db.DB, Options)`. The orchestrator no longer knows about CSAF-specific details; it just drives adapters and persists what they emit.

## [0.1.5] — Unreleased

### Added

- **CPE prefix matching on query path.** `/v1/resolve` and `/v1/sbom` now expand a queried CPE into both its exact form and its 5-part prefix (part:vendor:product:version:update). A scanner querying with `cpe:/o:redhat:enterprise_linux:8::baseos` now matches a statement keyed on `cpe:/o:redhat:enterprise_linux:8`. Implements Red Hat's documented matching contract; see [SECDATA-1220](https://redhat.atlassian.net/browse/SECDATA-1220).
- **Per-statement `source_format` field.** Every statement in the API response carries the upstream format it came from (`csaf` today; `oval` arrives in v0.2.0). All existing rows are backfilled to `csaf`.
- **Per-match `match_reason` field** on `/v1/resolve` and `/v1/sbom` responses: `direct`, `via_cpe_prefix`. Consumers can now see *why* a statement was returned.
- **`schema_version` table + forward-only migration runner.** Existing databases migrate in-place on first boot; rows are preserved.
- **Regression test** for the SECDATA-1220 scenario using the real Red Hat CSAF VEX document for CVE-2024-0217 (committed under `testdata/`).

### Fixed

- **CSAF extractor now inherits platform CPEs from `product_tree.relationships`.** Previously only the component side (`product_reference`, usually a PURL) was inherited into composite products, so Red Hat multi-stream advisories produced zero CPE-keyed statements. The extractor now also inherits from `relates_to_product_reference` (the platform side, where Red Hat puts the CPE). For `cve-2024-0217.json` this lifts CPE statement count from 0 to 41.
- **Ingest now plumbs `BaseID` and `Version`** from the csaf extractor to the DB layer. Previously these fields were dropped, and `db.BulkInsert` defaulted `base_id` to the full `ProductID`. Result: any scanner querying `/v1/resolve` or `/v1/sbom` with a versioned PURL got zero matches because the stored `base_id` also carried the vendor's own `@version` suffix. Now `base_id` is the normalized PURL base (no `@version`, no qualifiers) as intended.

### Changed

- `statements` primary key is now `(vendor, cve, product_id, source_format)`. Required so Phase 5 can coexist Red Hat CSAF and Red Hat OVAL statements for the same product without overwriting each other.
- `db.Statement` gained a `SourceFormat` field.
