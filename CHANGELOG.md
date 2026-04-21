# Changelog

All notable changes to reel-vex are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); reel-vex is pre-1.0 so minor bumps may carry breaking changes.

## [0.2.2] — Unreleased — OpenVEX opt-in output + native format as first-class

### Added

- **OpenVEX 0.2.0 output format on `/v1/resolve`.** Pass `"format": "openvex"` in the request body to receive an [OpenVEX 0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) document instead of the native reel-vex statements JSON. Designed for drop-in consumption by [`vexctl merge`](https://github.com/openvex/vexctl) and Trivy's `--vex` flag. Default behaviour is unchanged — native JSON remains the default response shape.
- **`docs/api.md` — canonical API reference.** Every endpoint, every response field, every `status` / `justification` / `source_format` / `match_reason` enum value documented in one place. Linked from the README header. The native response format is now a first-class, versioned interface rather than something you reverse-engineer from examples.
- **Input-echoing product resolution.** `/v1/resolve` now tracks which user-supplied product (in hierarchical base form — version and qualifiers stripped) expanded to each candidate base identifier. The OpenVEX encoder uses this map to place the user's PURL into each matched statement's `products[]`, so statements keyed on an upstream CPE (Red Hat OVAL) remain Trivy-matchable when queried via a PURL with `?repository_id=X`.
- **`pkg/openvex/`** package — stdlib-only OpenVEX 0.2.0 types + encoder. Includes deterministic content-hashed `@id` generation (`https://openvex.dev/docs/public/vex-<sha256>`), per-statement `timestamp` carried from the source `updated` field so `vexctl merge` orders correctly across vendors, vendor attribution via `supplier`, and diagnostic round-trip via `status_notes` (carries `source_format` and `match_reason`). The OpenVEX 0.2.0 JSON Schema is embedded in `pkg/openvex/testdata/` and its `required` fields are checked against encoded output in unit tests.

### Notes

- **Empty OpenVEX results return `204 No Content`.** The OpenVEX 0.2.0 schema requires `statements.minItems: 1`; rather than emit an invalid document when no statements match, the handler returns 204.
- **Trivy `--vex` matches on PURL only.** The encoder therefore emits user-supplied PURLs (not vendor CPEs) in `products[]`. Queries with only a CPE still produce a spec-valid document consumable by `vexctl` and Grype, but Trivy won't suppress anything.
- **No cryptographic signing yet.** `author` is a plain string; consumers relying on signed provenance should wait for the planned signed-attestations work.

## [0.2.1] — Unreleased

### Added

- **Structured `api_request` slog line per HTTP request.** Fields: `method`, `path`, `status`, `latency_ms`, `bytes`, plus `cve` on `/v1/cve/{id}[/summary]` routes. CORS preflight (`OPTIONS`) short-circuits before the log middleware, so no preflight noise. Consumers (Vector, Promtail, Fluent Bit, plain jq) can parse these with any slog-aware tooling and forward them anywhere; no vendor-specific SDK is embedded. Pure OSS observability improvement — operators running reel-vex anywhere get a machine-readable request log for free.

## [0.2.0] — Unreleased — multi-source Red Hat coverage

Plan-completion milestone. reel-vex now ingests Red Hat OVAL alongside CSAF, filling the EUS / AUS / E4S / SAP / HA / NFV stream coverage gap that Red Hat documented in [SECDATA-1181](https://redhat.atlassian.net/browse/SECDATA-1181) as intentional-but-asymmetric between their two feeds.

### Added

- **Red Hat OVAL source adapter** (`pkg/source/redhatoval/`). Fetches a single OVAL file per adapter instance (configurable via `url:`), decompresses bz2 in-stream, delegates parsing to the new [`getreeldev/oval-to-vex`](https://github.com/getreeldev/oval-to-vex) library, and emits VEX statements with `source_format: oval`. Incremental sync via HTTP `Last-Modified` — if upstream hasn't regenerated the file since our watermark, the adapter skips the GET entirely.
- **`source.Adapter.Vendor()` method**. Distinguishes the vendor domain (written onto statements) from the adapter instance ID (used for per-adapter watermarks). CSAF adapter's Vendor() returns its ID for backward compatibility; RH OVAL adapter's Vendor() returns `"redhat"` regardless of which OVAL file it targets. Two adapters for one vendor now produce statements under one vendor string, distinguished only by `source_format`.
- **`/v1/resolve` `source_formats` filter**. Request body accepts an optional `source_formats: ["csaf", "oval"]` array. Empty means all formats. Applied at the SQL `WHERE source_format IN (...)` layer.
- **`adapter_state` table** (schema v3). Keyed by adapter ID; holds per-adapter feed URL + last_synced watermark. Replaces the v2 `vendors.last_synced` / `vendors.feed_url` columns which were per-vendor and would collide when two adapters shared a vendor.
- Regression tests covering: the full Discover + Sync adapter lifecycle against an `httptest.Server` serving the committed OVAL fixture; HEAD-short-circuit when upstream is unchanged; source_formats filter at the API level with four scenarios (no filter / csaf-only / oval-only / both explicitly); schema v2 → v3 carry-forward preserving existing CSAF watermarks.

### Changed

- `statements.vendor` is now `a.Vendor()` (not `a.ID()`). For CSAF, unchanged in practice. For RH OVAL, statements carry `vendor: redhat` matching CSAF — no `redhat-oval` string appears in user-facing output.
- `ingest.Run` records per-adapter state via `UpsertAdapterState(adapterID, feedURL, lastSynced)` instead of `SetVendorSynced` / `UpsertVendor(…, feedURL)`. Watermark-preserving on no-op cycles (HEAD-short-circuit on OVAL, or CSAF runs with no new documents since last sync).
- `Stats.LastUpdated` reads `MAX(last_synced) FROM adapter_state`. JSON field name unchanged; semantics unchanged (newest upstream data absorbed across all adapters).
- `db.QueryResolve` signature: `QueryResolve(cves, products, sourceFormats)`. `sourceFormats` empty = no filter.
- `db.UpsertVendor` signature: `UpsertVendor(id, name)` (dropped `feedURL` argument — URL is now per-adapter, not per-vendor).
- `vendors` table schema: `last_synced` and `feed_url` columns dropped (v3 migration carries their values forward into `adapter_state` before drop).

### Migration

- Schema v2 → v3 runs on first boot of the new binary. Data-preserving:
  - `adapter_state` created and seeded from existing `vendors.{id, feed_url, last_synced}` rows.
  - `vendors.feed_url` and `vendors.last_synced` columns dropped after the copy.
  - Pre-existing CSAF watermark carries forward under the CSAF adapter's ID; first ingest after upgrade resumes from that timestamp (no full re-sync).
- Hosted deployment `config.yaml` must add one new entry for the Red Hat OVAL adapter. No rename of the existing CSAF `id: redhat`.

### Library

- New dependency: [`github.com/getreeldev/oval-to-vex v0.1.0`](https://github.com/getreeldev/oval-to-vex) — Red Hat OVAL XML parser + VEX-statement translator, zero dependencies beyond stdlib.

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
