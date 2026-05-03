# Changelog

All notable changes to reel-vex are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); reel-vex is pre-1.0 so minor bumps may carry breaking changes.

## [0.4.4] — `/v1/analyze` emits BOM-Link refs

Fixes downstream Trivy `--vex` consumption of the annotated CycloneDX returned by `/v1/analyze`. Trivy binds VEX statements to scan findings via BOM-Link refs in `affects[].ref` (per CycloneDX 1.5 VEX); the previous behaviour passed input PURLs through unchanged, which Trivy rejects with `WARN [vex] Unable to parse BOM-Link` and silently drops. With v0.4.4, the natural one-POST flow (`SBOM → /v1/analyze → trivy --vex`) suppresses findings end-to-end without manual VEX assembly.

### Fixed

- **`pkg/api/analyze.go`**: new `rewriteAffectsAsBOMLinks(sbom)` rewrites each `vulnerability.affects[].ref` from raw PURL to `urn:cdx:<serial>/<version>#<bom-ref>` form, using the input SBOM's `serialNumber`, `version`, and per-component `bom-ref` values. Best-effort: if any of those are missing, the original `.ref` is left in place. Runs unconditionally on the SBOM-output path so refs are spec-correct even when no vendor statements matched.

### Added

- **`TestRewriteAffectsAsBOMLinks_*`** (`pkg/api/analyze_bomlink_test.go`): five unit tests covering the rewrite, the string-shaped affects entry, missing serialNumber, unmatched ref, and component without bom-ref.
- **`TestAnalyze_EmitsBOMLinkRefsInAnnotatedSBOM`** (`test/integration/api_test.go`): end-to-end assertion that a Trivy-shape SBOM POSTed to `/v1/analyze` returns BOM-Link refs and an `analysis` block on the same vulnerability.

## [0.4.3] — Resolver bridge for scanner-emitted RPM `?distro=` qualifiers

Fixes `/v1/analyze` returning unannotated SBOMs for Trivy- and syft-generated CycloneDX inputs covering Red Hat content. Trivy emits RPM PURLs with a `?distro=redhat-X.Y` qualifier; mainstream Red Hat CSAF publishes bare PURLs without distro. The resolver previously produced only the SplitPURL-canonical candidate (which retains `?distro=`), so scanner queries missed the most common stored shape.

### Fixed

- **`pkg/resolver/resolver.go`**: `Expand()` now produces a distro-stripped candidate alongside the existing direct candidate when the input PURL carries `?distro=`. Purely additive on the read path: never removes a match, doesn't change write-side identity, no DB migration. Variant feeds that publish *with* distro (Red Hat Hummingbird, Ubuntu, Debian) continue to match via the unchanged distro-bearing candidate.

### Added

- **`TestExpand_RPMScannerDistroProducesBareAndDistroCandidates`** (`pkg/resolver/resolver_test.go`). Asserts both candidates appear for a Trivy-shape RPM input.
- **`TestAnalyze_AnnotatesTrivyShapeRPMSBOM`** (`test/integration/api_test.go`). End-to-end coverage: a CycloneDX SBOM with the realistic Trivy emission shape comes back with populated `analysis` blocks. The pre-existing `TestAnalyze_SBOMOnly_Annotates` used a clean PURL without scanner qualifiers and missed the regression vector.
- **`TestStatements_ResolvesTrivyShapeRPMToBareStored`** (`test/integration/api_test.go`). Same coverage at the `/v1/statements` query API.

### Changed

- **`TestExpand_PreservesDistroQualifier`** (`pkg/resolver/resolver_test.go`): tightened to assert the identity-preserving candidate is *present*, rather than that it's the only candidate. Original intent (distro is preserved) is unchanged.

## [0.4.2] — Unreleased — Canonical OpenVEX adapter

Adds a new adapter for Canonical's OpenVEX 0.2.0 feed at `https://security-metadata.canonical.com/vex/vex-all.tar.xz`. The feed is a strict superset of the existing Ubuntu OVAL coverage — it includes pre-USN triage state (`not_affected`, `under_investigation`) for every CVE Canonical has assessed, where the OVAL feed only ships `fixed` rows after a USN lands.

Both `ubuntu-vex` and `ubuntu-oval` adapters run during the soak window. Statements coexist in the database under different `source_format` values (`openvex` vs `oval`); the `statements` table PK includes `source_format`, so the two never collide. `ubuntu-oval` removal is queued for v0.5.0 once OpenVEX parity is verified in production.

### Added

- **`ubuntu-vex` adapter** (`pkg/source/ubuntuvex/`). Streaming xz + tar walk. HEAD/`Last-Modified` incremental skip on the tarball. Ignores USN-keyed entries; logs and skips malformed entries. Emits one row per (statement × unique normalized identifier).
- **ESM-track distro normalisation** (`pkg/source/ubuntuvex/distro.go`). Constant table mapping Canonical's `?distro=` qualifier values (`ubuntu/<codename>`, `esm-apps/<codename>`, `esm-infra/<codename>`, `esm-infra-legacy/<codename>`) to scanner-convention `ubuntu-<version>`. No external alias file; many-to-one collisions deduped at emit time.
- **`source_format=openvex`** as a new value in `db.Statement.SourceFormat`, surfaced in OpenVEX `status_notes` automatically.
- New direct dep: `github.com/ulikunitz/xz` (pure-Go, MIT, no cgo). Required for the tar.xz feed format.

### Changed

- **`pkg/openvex/identifiers.go`** (new): `CollectIdentifiers([]Component) []string` extracted from `pkg/uservex/parse.go` so both inbound user-VEX parsing and the new adapter share the dedup logic. Pure refactor; `pkg/uservex` behaviour is unchanged.
- **`config.yaml`**: new `ubuntu-vex` entry; existing `ubuntu-oval-*` entries flagged with a deprecation comment.

### Changed

- **Ingest architecture for `ubuntu-vex`**: the tarball is buffered fully into memory before the xz/tar walk begins, then processed locally. The original streaming-through-HTTP-body design coupled the connection lifetime to the walk duration — staging surfaced this when a 47-minute walk tripped the 15-minute HTTP timeout. The tarball is ~59 MB compressed; in-memory buffering removes the HTTP/walk coupling entirely.
- **`/v1/stats` now serves a cached struct** updated at the end of each ingest cycle. Before this change, every call ran four `COUNT(*)` / `COUNT(DISTINCT)` queries over the full statements table — fine on the v0.4.1-era 13M-row DB (~1s) but unacceptable on the v0.4.2-era ~145M-row DB (30-60s). The cache is exact (not approximate), refreshed in `pkg/db/db.go:RefreshStats()` from the orchestrator at the end of `ingest.Run`, and warmed at server startup via a background goroutine. Tests that mutate the DB and re-read stats must call `RefreshStats` between mutation and read.

### Notes

- No breaking changes; this is a patch bump matching the v0.2.3 (Ubuntu OVAL) and v0.2.6 (Debian OVAL) precedent for new adapters.
- The Canonical tarball regenerates daily-ish; `Last-Modified` skip saves CPU but not bandwidth on cycles where the upstream did regenerate.
- Per-entry tar mtime prune (a finer-grained incremental optimisation) is deferred to v0.4.3 if profiling shows the full re-emit is too expensive at production cadence.
- **`ubuntu-oval` is intentionally retained** alongside `ubuntu-vex`. Empirical staging parity check (8-CVE sample on prod-snapshot data) found OVAL contributes ~10% of unique `(cve, base_id)` tuples that OpenVEX uses different naming for (versioned binary packages like `golang-1.20-go`, source vs binary package families, etc.). Both feeds together give consumers the union of identifier shapes; storage cost is trivial. The Phase F removal originally planned for v0.5.0 is cancelled.

## [0.4.1] — Unreleased — rename `customer_vex` → `user_vex`

> **Breaking change.** The `customer_vex` request field on `POST /v1/analyze` is renamed to `user_vex`, and the `from_customer_vex` match-reason value (carried in OpenVEX `status_notes`) is renamed to `from_user_vex`. "Customer" implied a paid-product relationship that doesn't apply to the free OSS hub — the document is supplied by the API user, not a customer. No semantic change; pure rename.
>
> Migration:
>
> | Old | New |
> |---|---|
> | Request field `customer_vex` on `POST /v1/analyze` | `user_vex` |
> | `match_reason=from_customer_vex` in `status_notes` | `match_reason=from_user_vex` |
> | Go package `pkg/customervex/` | `pkg/uservex/` |

### Changed

- **`POST /v1/analyze` request field** `customer_vex` → `user_vex`. Documents posted under the old key are rejected with the standard "at least one of sbom or user_vex required" 400.
- **OpenVEX `status_notes`** match-reason value `from_customer_vex` → `from_user_vex` for user-supplied rows.
- **Go package** `pkg/customervex/` → `pkg/uservex/`. Public symbols (`Parse`, `Validate`, `Merge`, `MatchReason`) keep their names; only the import path changes. `MatchReason` constant value updates from `"from_customer_vex"` to `"from_user_vex"`.
- **Documentation**: `docs/api.md` and `README.md` updated; user-facing prose drops "customer" terminology throughout.

### Notes

- No production users on the deployed hosted instance to migrate. Companion website (`getreel.dev/vex`) renames its UI copy and curl examples in lockstep.
- Output shape, merge semantics, override rules, limits, and privacy posture are unchanged from v0.4.0.

## [0.4.0] — Unreleased — unified `/v1/statements` query endpoint

> **Breaking change.** Three v0.3.0 endpoints are removed and replaced by a single `POST /v1/statements`. The split between `/v1/cve/{id}` (CVE-only lookup) and `/v1/resolve` (CVE × product matrix) was a transport-level convenience, not a semantic distinction; v0.4.0 collapses them into one filter-rich query primitive.
>
> Migration:
>
> | Old | New |
> |---|---|
> | `GET /v1/cve/{id}` | `POST /v1/statements` with `{"cves": ["<id>"]}` |
> | `GET /v1/cve/{id}/summary` | No replacement; was unused. The website computes per-CVE breakdown client-side from the full statement list. |
> | `POST /v1/resolve` | `POST /v1/statements` with the same body shape |
>
> All three old paths return `404` after the upgrade. URLs like `https://vex.getreel.dev/v1/cve/<id>` shared in bookmarks or chat will break — the trade-off for unifying the API behind one query primitive.

### Added

- **`POST /v1/statements`** — unified query primitive over the VEX statements database. Replaces `/v1/cve/{id}`, `/v1/cve/{id}/summary`, and `/v1/resolve`. `cves` is required (≥1); every other filter is optional and narrows the result set further.
- **Four new filter dimensions** beyond v0.3.0's `source_formats`:
  - `vendors` — `["redhat"]`, `["redhat", "suse"]`, etc.
  - `statuses` — `["not_affected", "fixed"]`. Useful for noise-reduction policies.
  - `justifications` — OpenVEX 0.2.0 enum values. Filters to `not_affected` rows with the given justifications.
  - `since` — RFC3339 timestamp; statements with `updated >= since`. Enables incremental sync from a downstream cache.

  Filter semantics: AND across populated dimensions, IN within each non-empty list. Empty list (or omitted field) → no filter on that dimension. `source_formats` carries forward from v0.3.0 unchanged.

### Removed

- `GET /v1/cve/{id}` — returns `404`. Migrate to `POST /v1/statements` with `{"cves": ["<id>"]}`.
- `GET /v1/cve/{id}/summary` — returns `404`. The website computes the breakdown client-side; no migration needed.
- `POST /v1/resolve` — returns `404`. Migrate to `POST /v1/statements` (same body shape).
- Internal: `db.QueryByCVE` and `db.QueryResolve` are deleted; replaced by `db.QueryStatements(QueryFilters)` with a struct-based filter parameter.

### Changed

- **CVE-only queries are POST now.** The browser-friendly `GET /v1/cve/{id}` URL is gone. The trade-off: one canonical query method that scales to N filters cleanly. URLs the website previously shared (e.g. `getreel.dev/vex?cve=CVE-X`) still work — the website does the POST internally.
- **`/v1/analyze` flow internals**: the SBOM-merge code path now calls `db.QueryStatements` instead of `db.QueryResolve`. No external behaviour change; covered by existing regression tests.

### Notes

- The encoder (`pkg/openvex/Encode`) is unchanged. CVE-only queries (no `products`) get nil expansion maps and the encoder falls back to each statement's stored `product_id` — same shape `/v1/cve/{id}` produced in v0.3.0. CVE+products queries echo the user's input PURLs into `products[]` — same shape `/v1/resolve` produced.
- `vexctl merge` interop verified end-to-end against `/v1/statements` output (existing integration test renamed; same behaviour).
- All existing `/v1/analyze` behaviour is preserved (override semantics, user-VEX merge, sample fixtures).

## [0.3.0] — Unreleased — API format unification + user-VEX merge

> **Breaking changes — three migrations.** This release folds long-standing API tidying into one cut so future migrations stay singular.
>
> 1. **`POST /v1/sbom` is removed.** Migrate to `POST /v1/analyze` with `{"sbom": <cyclonedx>}` wrapping. The annotation logic and CycloneDX output shape are unchanged; only the request envelope and route differ. Requests to the old route now return `404`.
> 2. **`/v1/resolve` always returns OpenVEX 0.2.0.** The `format` request field is removed; the reel-vex-native flat response is gone. Existing OpenVEX consumers (Trivy `--vex`, `vexctl`) are unaffected. Native-format consumers must migrate to OpenVEX — `source_format` and `match_reason` are now carried in `status_notes` (`source_format=csaf; match_reason=direct` etc.).
> 3. **`/v1/cve/{id}` returns OpenVEX 0.2.0.** Empty results return `204 No Content` instead of a 200 with an empty array (OpenVEX schema requires `statements: minItems 1`). `/v1/cve/{id}/summary` is unaffected — it serves a separate counts-style response.

### Added

- **`POST /v1/analyze` — single endpoint for SBOM annotation and user-VEX merging.** Accepts an SBOM (CycloneDX 1.4+), one or more user-supplied OpenVEX 0.2.0 documents, or both:
  - `sbom` only → annotated CycloneDX (preserves prior `/v1/sbom` behaviour byte-for-byte).
  - `user_vex` only → merged OpenVEX 0.2.0 doc (vendor data + user's claims, with override on collision).
  - Both → annotated CycloneDX where the per-CVE rollup honours user override.
  Inline JSON only; no multipart, no URL fetch.
- **User-VEX merge with absolute override.** User statements override vendor statements when `(cve, base_id)` matches. In the SBOM-annotation flow, user-asserted CVEs are tracked in a set so vendor rows are excluded from the per-CVE rollup — even when they sit at a different base_id. Without this guard, a higher-priority vendor `not_affected` would silently outrank a user `affected` on a different identifier.
- **New `pkg/uservex/`** package: parses OpenVEX 0.2.0 inbound, validates against a leaner inbound-only ruleset (separate from `pkg/openvex.Validate` which is outbound-focused), enforces request-time limits, and merges with vendor data. User VEX is processed strictly in memory: parsed, merged, returned, discarded. No source-tree code logs or persists user payload content.
- **`from_user_vex` match reason.** User-sourced rows in OpenVEX output carry `status_notes` with `match_reason=from_user_vex` (no `source_format=` prefix, since user rows have no upstream feed).

### Changed

- **`pkg/openvex` is the single response writer for VEX-statement-emitting endpoints.** Replaces the prior native scaffolding (`statementJSON`, `statementsResponse`, `writeStatements`, `writeStatementsWithMatch`) which is deleted from source.
- **`csaf.SplitPURL` consolidates the PURL-base-normalisation logic.** The previously private `resolver.splitBase` (line-for-line equivalent) is removed; `pkg/resolver` now imports `pkg/csaf` and calls `SplitPURL` directly. Single source of truth.
- **`pkg/openvex/encode.go` skips the `source_format=` prefix in `status_notes`** when the source row's `SourceFormat` is empty (user-sourced rows). Vendor rows are unchanged.
- **Limits on `/v1/analyze`**: 5 MB body; 10 user_vex docs / 1000 user statements / 100 products per user statement; 50 000 SBOM components / 10 000 SBOM vulnerabilities. 4xx codes split: 400 for limit overflow / shape requirements; 422 for spec-violation rejections (bad `@context`, status enum, justification placement, missing required fields).

### Removed

- **`POST /v1/sbom`** — return `404`. Use `POST /v1/analyze` with `{"sbom": <cyclonedx>}`.
- **`format` request field on `/v1/resolve`** — OpenVEX is the only format. Trying to send `format: ...` is silently ignored (Go JSON decoder drops unknown fields).
- **Native flat response shape** (`{vendor, cve, product_id, ...}` rows). All endpoints emit OpenVEX 0.2.0. The `cve` / `vendor` / `product_id` semantic content is preserved as `vulnerability.name` / `supplier` / `products[].@id` (or `products[].identifiers.{purl,cpe22,cpe23}`); `source_format` / `match_reason` move into `status_notes`.

### Notes

- `source_formats` request filter on `/v1/resolve` is unchanged — it still restricts which upstream feeds match. Filtering happens at query time; the filter is a request parameter, not a response annotation.
- Empty `/v1/resolve` results have always returned `204` for OpenVEX output. This is now the default since OpenVEX is the only output.
- The `@id` of any emitted document is a deterministic SHA-256 over the canonical body (timestamps zeroed); identical queries produce byte-identical `@id`s. Useful for caching.

## [0.2.6] — Unreleased — Debian OVAL adapter

### Added

- **Debian OVAL adapter** (`pkg/source/debianoval`). Ingests Debian Security Tracker OVAL feeds, delegating parse/translate to [`oval-to-vex` v0.2.2](https://github.com/getreeldev/oval-to-vex)'s new `FromDebianOVAL`. Adds Debian coverage alongside Red Hat, SUSE, and Ubuntu — completing the major deb/rpm vendor set for typical container bases and bare-metal Linux fleets.
- **Default config wires three releases**: `bullseye` (11), `bookworm` (12), `trixie` (13). Buster (10) is end-of-life and Debian no longer publishes its OVAL feed; add it back if needed against an archived feed mirror.

### Notes

- **Identifier shape**: `pkg:deb/debian/<name>?distro=debian-<N>`. The `distro` qualifier is part of `BaseID` (same approach as Ubuntu) so bookworm `openssl` and bullseye `openssl` are distinct products. The v0.2.5 resolver fix (preserve `distro` in `splitBase`) means scanner queries with `?distro=debian-12` match correctly out of the box.
- **Status mapping** (mirror model — report what the vendor publishes, let consumers decide):
  - `class="patch"` or `class="vulnerability"` with a dpkginfo evr bound → `status="fixed"`, `version=<evr>`
  - `class="vulnerability"` with no resolvable dpkginfo test → `status="affected"` (empty version) keyed on the `<product>` name from metadata — Debian's tracker knows the CVE applies but no patch has shipped yet
  - Consistent with our Red Hat OVAL posture. Trivy 0.70.0 was empirically verified to accept `affected`-containing VEX documents without errors. Debian's current feed happens not to include unpatched-vuln records in practice (every `class="vulnerability"` definition ships with a fix bound today), so the affected branch is mostly latent coverage for future records.
- **Volume**: Bookworm alone has ~46k statements (Ubuntu noble is ~24k for comparison); per-release volume is high because Debian's tracker is comprehensive — every CVE that ever affected the release, going back decades.

## [0.2.5] — Unreleased — preserve `distro` qualifier on PURL base IDs

### Fixed

- **`/v1/resolve` now matches Ubuntu (and any deb) statements.** Both `csaf.SplitPURL` and the resolver's private `splitBase` were stripping *all* qualifiers from input PURLs, so a query for `pkg:deb/ubuntu/openssl@...?distro=ubuntu-24.04` was normalised to `pkg:deb/ubuntu/openssl` and never matched the stored Ubuntu `base_id` which carries the `distro` qualifier. Both functions now preserve `distro`, which is identity for deb packages — noble `openssl` and jammy `openssl` are different packages with different fixed versions. `arch`, `epoch`, `repository_id` remain scanner-side filters and are still stripped.
- Symptom was visible on the hosted deployment after v0.2.4 landed Ubuntu ingest: `/v1/cve/<id>` returned Ubuntu statements correctly, but `/v1/resolve` with a versioned PURL returned empty. No effect on RH or SUSE queries (no `distro` qualifier in use).

## [0.2.4] — Unreleased — switch Ubuntu adapters to main USN feeds

### Changed

- **Ubuntu OVAL adapters now point at the main USN feeds** (`com.ubuntu.<release>.usn.oval.xml.bz2`) instead of the OCI variants (`oci.com.ubuntu.<release>...`). The OCI feeds use a different OVAL test model (`textfilecontent54_*` rather than `dpkginfo_*`) that the adapter does not parse — v0.2.3 therefore ingested zero statements from them in practice. The fix is not to teach the adapter the OCI shape; it is to use the feed that carries everything Canonical publishes.
- **Adapter IDs dropped the `-oci` suffix** to reflect the swap: `ubuntu-oval-noble`, `ubuntu-oval-jammy`, `ubuntu-oval-focal`. On the hosted deployment the existing `-oci`-suffixed adapter_state rows are left in place (with zero statements) and new rows are created under the new IDs on first sync.

### Rationale

vex.getreel.dev is a general VEX hub, not a container scanner. Scoping vulnerability data to "container-relevant" packages is a decision the scanner should make, based on what it is scanning — a container image, a VM filesystem, a bare-metal host, an initramfs. Our Red Hat and SUSE adapters already ingest the full vendor feeds; scoping Ubuntu to a subset broke symmetry for no principled reason. A consumer scanning a bare-metal Ubuntu host would otherwise receive less coverage from us than they would for the equivalent RHEL host.

## [0.2.3] — Unreleased — Ubuntu OVAL adapter

### Added

- **Ubuntu OVAL adapter** (`pkg/source/ubuntuoval`). Ingests Canonical's USN OVAL feeds, delegating parse/translate to [`oval-to-vex` v0.2.0](https://github.com/getreeldev/oval-to-vex)'s new `FromUbuntuOVAL`. Adds non-distroless Ubuntu coverage — the highest-volume container base — alongside existing Red Hat and SUSE sources.
- **Default config wires OCI feeds for focal/jammy/noble.** Three `ubuntu-oval` adapter entries in `config.yaml` pointing at Canonical's OCI-flavoured feeds (`oci.com.ubuntu.<release>.usn.oval.xml.bz2`) — kernel/HWE noise stripped, focused on container-scanning use cases. Main-feed adapters can be added by pointing a new entry at `com.ubuntu.<release>.usn.oval.xml.bz2`.

### Notes

- **Identifier shape.** Ubuntu statements emit PURLs in the form `pkg:deb/ubuntu/<name>?distro=ubuntu-<version>`. The distro qualifier is part of `BaseID` (not just `ProductID`) — noble `openssl` and jammy `openssl` are distinct products, since the fixed versions differ per release.
- **Patches only, for now.** Ubuntu's USN OVAL feed publishes `class="patch"` statements only. Unfixed/"affected" statements live in Canonical's separate CVE OVAL feed, which is a future adapter.
- **Supported release codenames** are `focal`, `jammy`, `noble`. Definitions for unsupported codenames are skipped by the translator; add new entries to the codename-version map in `oval-to-vex` when Canonical ships a new LTS.
- **USNs with no CVE references are skipped.** Rare in practice (USNs almost always have ≥1 CVE); emitting USN-keyed statements as a fallback is future work.

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
