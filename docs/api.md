# reel-vex API reference

Canonical reference for every HTTP endpoint and response field. The live service is at `https://vex.getreel.dev`; the same binary powers any self-hosted deployment.

- [Endpoints](#endpoints)
- [Response format — OpenVEX 0.2.0](#response-format--openvex-020)
- [`POST /v1/statements`](#post-v1statements)
- [`POST /v1/analyze`](#post-v1analyze)
- [Recipes](#recipes)

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/statements` | Unified query: explicit `cves`/`products` lists, or a CycloneDX SBOM (or both); filter by vendor, status, justification, source format, or update timestamp. Returns OpenVEX 0.2.0 — for `trivy image --vex` and any tool that prefers portable identifiers. |
| `POST` | `/v1/analyze` | Annotate a CycloneDX SBOM in place and/or merge user-supplied VEX with vendor data. Returns CycloneDX (with BOM-Link refs) — for `trivy sbom --vex`. |
| `GET`  | `/v1/stats` | Coverage statistics. Cache-backed; refreshed at the end of each ingest cycle. |
| `GET`  | `/v1/ingest` | Current ingest status. |
| `POST` | `/v1/ingest` | Trigger a manual ingest (admin token). |
| `GET`  | `/healthz` | Liveness probe. |

The two SBOM-accepting endpoints serve distinct missions:

- `/v1/statements` — return OpenVEX 0.2.0; input may be explicit identifier lists, an SBOM, or both. Use for `trivy image --vex` and any consumer that takes portable VEX docs.
- `/v1/analyze` — return CycloneDX in place (annotated SBOM, BOM-Link refs in `affects[].ref` for spec-correct Trivy `--vex` consumption). Use for `trivy sbom --vex`.

## Response format — OpenVEX 0.2.0

Every VEX-statement-emitting endpoint (`/v1/statements`, `/v1/analyze` when `user_vex`-only) returns an [OpenVEX 0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) document. There is no opt-in flag and no alternative response format; OpenVEX is the single canonical interchange format reel-vex serves.

Per-feed provenance (`source_format`) and per-statement match reasoning (`match_reason`) are carried in the spec-blessed `status_notes` free-text field. Format: `source_format=<csaf|oval|openvex>; match_reason=<direct|via_alias|via_cpe_prefix|from_user_vex>`, plus `scope=<product @id>` on product-scoped rows (Rancher VEX — see [Product-scoped statements](#product-scoped-statements)). User-sourced rows omit the `source_format=` prefix entirely (no upstream feed).

Empty results return `204 No Content`. OpenVEX 0.2.0's schema requires `statements: minItems 1`, so a valid document with zero statements cannot be emitted; 204 signals "query valid, no statements" without violating the schema.

### Statements are grouped by assertion, not by database row

**Changed in 0.12.0.** One statement carries every product it applies to. Rows that agree on *every* statement-level field — CVE, status, justification, supplier, timestamp, and the whole of `status_notes` — are emitted once, with `products[]` holding the union of their subjects. Anything that differs on any of those fields stays a separate statement, so a CSAF row and an OVAL row, a `direct` match and a `via_alias` match, or a scoped and an unscoped verdict are never merged.

This matters for two reasons.

It is what the format asks for: `products[]` is an array precisely so one assertion can name many subjects, and OpenVEX 0.2.0 declares `statements` with `uniqueItems: true`. Before 0.12.0 reel-vex emitted one statement per row, and because a query that supplies `products` echoes the caller's identifier in base form — no version, no arch — the eight architectures and five package versions a distro publishes for one advisory all rendered as byte-identical statements. A real `ubuntu:22.04` SBOM query returned 13 543 statements of which 12 215 were duplicates, and the document failed schema validation.

And it changes what a statement count means. `statements[]` now counts distinct assertions, so the same query returns far fewer entries than before (that `ubuntu:22.04` query: 13 543 → 750). Nothing is dropped — every product in the old response is still in the new one. The row count is still available in `X-Reel-Statements`, which is unchanged.

Consumers that iterate `products[]` need no change. Trivy 0.74.0 suppresses the identical set of CVEs from a grouped and an ungrouped document.

### Document-level fields

| Field | Type | Description |
|---|---|---|
| `@context` | string | `https://openvex.dev/ns/v0.2.0`. Always present. |
| `@id` | string | Deterministic SHA-256 of the document body (with timestamps zeroed): `https://openvex.dev/docs/public/vex-<hex>`. The same query produces the same `@id` byte-for-byte. |
| `author` | string | `reel-vex aggregator <vex@getreel.dev>`. reel-vex acts as an aggregator and does not sign documents. |
| `role` | string | `aggregator`. |
| `timestamp` | RFC3339 string | When this document was emitted. |
| `version` | integer | Document revision; always `1`. |
| `statements` | array | At least one statement (per OpenVEX schema). |

### Statement fields

| Field | Type | Description |
|---|---|---|
| `vulnerability.name` | string | The CVE ID (e.g. `CVE-2021-44228`). |
| `products[]` | array | Every product this statement applies to — deduped and ordered by identifier. Each carries an `@id` and/or an `identifiers` object with `purl`/`cpe22`/`cpe23`. When the request includes `products` (`/v1/statements`, `/v1/analyze`), the user's input identifier is echoed verbatim into `products[]` so consumers like Trivy that match on PURL see what they sent. Iterate the whole array; do not assume `products[0]`. |
| `status` | string | One of the four VEX statuses (see [Status values](#status-values)). |
| `status_notes` | string | Diagnostic free text: `source_format=<csaf|oval|openvex|secdb|updateinfo>; match_reason=<...>`, plus `scope=<product @id>` on product-scoped rows. Empty `source_format=` is omitted on user-sourced rows. |
| `justification` | string | Required when `status==not_affected`. OpenVEX 0.2.0 enum (see [Justification values](#justification-values)). |
| `supplier` | string | Vendor identifier (`redhat`, `suse`, `rancher`, `ubuntu`, `debian`, `alpine`, `amazon`, `almalinux`, `oracle`). For user-sourced rows, the value the user self-disclosed via the inbound doc's `supplier` field. |
| `timestamp` | RFC3339 string | When the upstream advisory (or user document) last updated this statement. |

### Status values

| Value | Meaning |
|---|---|
| `not_affected` | The vendor has confirmed this product is not impacted by the CVE. Usually paired with a `justification`. |
| `affected` | The vendor has confirmed this product is impacted. |
| `fixed` | A fix is available; consumers should upgrade. |
| `under_investigation` | Vendor has not yet determined impact. |

reel-vex publishes whatever status the vendor stated — including `affected` and `under_investigation`. Trivy's `--vex` flag suppresses on `not_affected` and `fixed` and ignores the other two; `vexctl` and custom policy engines may treat them differently. Filter client-side for a narrower set.

### Justification values

Only meaningful when `status == "not_affected"`. Values match the OpenVEX 0.2.0 enum.

| Value | Meaning |
|---|---|
| `component_not_present` | The vulnerable component isn't in the product at all. |
| `vulnerable_code_not_present` | The component is present, but the vulnerable code path isn't built in. |
| `vulnerable_code_not_in_execute_path` | Code is present but unreachable in this configuration. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | Code is reachable but an attacker can't reach the trigger condition. |
| `inline_mitigations_already_exist` | Runtime mitigation neutralises the vulnerability. |

### Match reasons

Carried in `status_notes` as `match_reason=<value>`. Identifies which rule caused the statement to match the query.

| Value | Meaning | Precedence |
|---|---|---|
| `from_user_vex` | This row came from the request's `user_vex` payload, not from any vendor feed. User rows override vendor rows on `(cve, base_id)` collision. | 1 (strongest, override) |
| `direct` | The query's normalised base identifier equals the statement's stored base. | 2 |
| `via_alias` | The query carried a `?repository_id=X` PURL qualifier, and reel-vex's alias table maps that repository ID to a CPE that matches the statement. | 3 |
| `via_cpe_prefix` | The query is a CPE 2.2 URI, and its 5-part prefix (`part:vendor:product:version:update`) matches the statement — implements Red Hat's [SECDATA-1220](https://redhat.atlassian.net/browse/SECDATA-1220) contract. | 4 |

When the same candidate is produced by multiple rules, the strongest reason wins.

### PURL identity rules

For PURL-keyed statements, qualifiers behave in two distinct modes:

| Qualifier | Mode | Effect |
|---|---|---|
| `distro` (deb) | identity | Part of the statement's `base_id` — `pkg:deb/debian/openssl?distro=debian-12` is a different identity from `pkg:deb/debian/openssl?distro=debian-11`. **Required** on deb-shaped queries to match Debian and Ubuntu OVAL/OpenVEX statements. |
| `distro` (rpm) | strip-and-also | Trivy and syft emit RPM PURLs with `?distro=redhat-X.Y`, but Red Hat CSAF publishes bare PURLs without distro. The resolver therefore expands a distro-bearing RPM input into both the input-as-given **and** a distro-stripped candidate — purely additive, so a Trivy-shape RPM input matches bare-stored Red Hat statements without losing identity-aware matching against feeds that publish *with* distro. |
| `repository_id` | filter | Stripped from `base_id`; used by the alias resolver to expand to a CPE (`via_alias`). Required on Red Hat queries that need EUS / AUS / E4S coverage. |
| `arch` | stripped by default | Not part of `base_id`, so matching ignores architecture by default. This is deliberate: the feeds disagree about whether to qualify at all (Canonical's OpenVEX qualifies ~100% of rows, Red Hat CSAF ~69%, every other source 0%), so matching exactly would turn most of the corpus into false negatives. Set [`strict_arch`](#architecture-matching-strict_arch) to narrow. |
| `epoch` | stripped | Not part of identity; ignored when matching. |

### Product-scoped statements

Most feeds are package-level — a statement is about a package, full stop. The Rancher VEX hub is **product-scoped**: a `not_affected` verdict is about a specific image or Go module (the *scope*), and the package it concerns rides in an OpenVEX subcomponent. reel-vex stores the package as the queryable `product_id` / `base_id` and the product `@id` as the row's `scope`.

A scoped statement matches **only when the caller names its scope** — otherwise it is withheld, so a verdict scoped to one image can never suppress the same package for an unrelated one. Supply the scope two ways:

- **`/v1/statements`** — pass the product/image identifier(s) in the `scopes` array. When an SBOM is POSTed instead, its root subject (`metadata.component`) supplies the scope automatically.
- **`/v1/analyze`** — the SBOM's `metadata.component` (purl/cpe) is used automatically as the scope, so scanning an image applies exactly the verdicts scoped to it.

With no scope context, only unscoped (package-level) rows are returned — every other feed behaves exactly as before. Scopes are normalised before matching (the OCI `repository_url` is kept, the tag/digest dropped), and a matched scoped row discloses its scope in `status_notes` as `scope=<product @id>`.

## `POST /v1/analyze`

Single endpoint for SBOM annotation and user-VEX merging. Accepts either or both inputs. Replaces the v0.2.x `/v1/sbom` endpoint.

### Request

```json
POST /v1/analyze
Content-Type: application/json

{
  "sbom": { /* CycloneDX 1.4+ */ },                 // optional
  "user_vex": [                                  // optional; OpenVEX 0.2.0 or CycloneDX VEX (normalised to OpenVEX)
    { "@context": "https://openvex.dev/ns/v0.2.0", "statements": [ /* ... */ ] }
  ]
}
```

At least one of `sbom` or `user_vex` must be present; otherwise `400`. Inline JSON only — `multipart/form-data` is not accepted.

Each `user_vex` document must carry `@context = "https://openvex.dev/ns/v0.2.0"`; otherwise `422`. The reel-vex-native flat format is not accepted as input anywhere in the API.

### Output

| Input combination | Response |
|---|---|
| `sbom` with non-empty `vulnerabilities[]` | Annotated CycloneDX (vulnerability `analysis` blocks added in place; `vulnerability.affects[].ref` rewritten as BOM-Link). |
| `sbom` with empty/absent `vulnerabilities[]` | CycloneDX with `vulnerabilities[]` **synthesised** from a broad-mode lookup over the components, then annotated (see below). |
| `user_vex` only | OpenVEX 0.2.0 doc (merged vendor + user with override on collision). |
| Both | Annotated CycloneDX where the per-CVE rollup honours user override; `affects[].ref` rewritten as BOM-Link. |
| Neither | `400` with `at least one of sbom or user_vex required`. |

**BOM-Link refs.** On the annotated-CycloneDX path, every `vulnerability.affects[].ref` is rewritten from raw PURL to the CycloneDX 1.5 BOM-Link form `urn:cdx:<serialNumber>/<version>#<bom-ref>`, using the input SBOM's `serialNumber`, `version`, and per-component `bom-ref`. This is what `trivy sbom --vex` binds against; without it, Trivy logs `WARN [vex] Unable to parse BOM-Link` and silently drops statements. Best-effort: if the input SBOM is missing `serialNumber`, the component has no `bom-ref`, or the affected ref doesn't map to any component in the SBOM, the original `.ref` is left in place.

**Product-scoped statements.** Vendor statements scoped to a product (Rancher VEX) are applied only when the SBOM's `metadata.component` matches their scope — scanning an image automatically opts in the verdicts scoped to it, and never applies one scoped to a different image. See [Product-scoped statements](#product-scoped-statements).

### SBOM with no vulnerabilities — broad-mode synthesis

When the input SBOM's `vulnerabilities[]` is empty or absent, `/v1/analyze` runs a **broad-mode** vendor lookup over the SBOM's components (every CVE touching them, no CVE filter — the same query `/v1/statements` broad mode uses) and **synthesises** one `vulnerabilities[]` entry per matched CVE before annotating. Each synthesised entry carries `affects[]` pointing at the affected components (rewritten to BOM-Link form like any other), and an `analysis` block from the vendor data. This lets a consumer POST a components-only SBOM and get back a fully VEX-populated CycloneDX document in one call — no intermediate OpenVEX → CycloneDX translation.

Rule: **empty-in → populate from broad mode; non-empty-in → annotate only.** A SBOM that already carries `vulnerabilities[]` is annotated exactly as before; broad-mode CVEs are never added on top of a populated list.

The synthesised set is capped by `-statements-max` (default 50 000). If the cap is hit, the response stays `200 OK` with `X-Reel-Truncated: true` and some CVEs are omitted — re-scope the request (e.g. fewer components) for complete coverage.

### User-VEX merge semantics

- **Collision rule**: user statements override vendor statements when `(cve, base_id)` matches. `base_id` is computed by stripping PURL version + filter qualifiers (keeping `distro`); CPEs are passed through as-is.
- **Annotation override**: when a user asserts on a CVE, vendor rows for that CVE are excluded from the SBOM-annotation per-CVE rollup — even when the vendor row sits at a different `base_id`. This guards against a higher-priority vendor `not_affected` outranking a user `affected` on a different identifier.
- **Self-collisions**: two user statements on the same `(cve, base_id)` dedupe by latest `timestamp`; ties break by list order.
- **Match reason**: user-sourced rows in OpenVEX output carry `status_notes` with `match_reason=from_user_vex` (no `source_format=` prefix).
- **Supplier**: user's `supplier` field flows through verbatim to the response.

### User-VEX timestamps

When a user statement omits both per-statement `timestamp` and the doc-level `timestamp`, reel-vex stamps the statement with the request's processing time. Users that care about deterministic timestamps should set them explicitly.

### Privacy

User VEX submissions are processed in memory: parsed, validated, merged, returned, discarded. No part of reel-vex source code logs or persists user payload content.

### Limits

| Rule | Value | Status |
|---|---|---|
| Request body size | 10 MB | `413` |
| `user_vex` documents per request | 10 | `400` |
| User statements (total across docs) | 25 000 | `400` |
| Products per user statement | 100 | `400` |
| SBOM components | 50 000 | `400` |
| SBOM vulnerabilities | 10 000 | `400` |
| At least one of `sbom`/`user_vex` | required | `400` |
| OpenVEX `@context` exact match `https://openvex.dev/ns/v0.2.0` | required | `422` |
| Status / justification enum compliance | required | `422` |
| `status==not_affected` requires a `justification` | required | `422` |
| Each product has at least one of `@id`, `identifiers.purl`, `identifiers.cpe22`, `identifiers.cpe23` | required | `422` |

### Example — SBOM only

```bash
curl -X POST https://vex.getreel.dev/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"sbom": '"$(cat sbom.json)"'}' > annotated.json
```

### Example — user VEX only

```bash
curl -X POST https://vex.getreel.dev/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "user_vex": [{
      "@context": "https://openvex.dev/ns/v0.2.0",
      "statements": [{
        "vulnerability": {"name": "CVE-2021-44228"},
        "products": [{"@id": "pkg:rpm/redhat/log4j"}],
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "supplier": "acme",
        "timestamp": "2026-04-20T00:00:00Z"
      }]
    }]
  }' > merged-vex.json
```

### Example — both inputs

```bash
jq -n \
  --argjson sbom "$(cat sbom.json)" \
  --argjson vex  "$(cat user-vex.json)" \
  '{sbom: $sbom, user_vex: [$vex]}' | \
curl -X POST https://vex.getreel.dev/v1/analyze \
  -H "Content-Type: application/json" \
  -d @- > annotated-with-override.json
```

## `POST /v1/statements`

Unified query primitive over the VEX statements database. The query input set may be specified explicitly (via `cves` and/or `products` lists), derived from a CycloneDX SBOM, or both. Everything else is an optional filter that narrows the result further. Returns an OpenVEX 0.2.0 document; 204 on empty match.

Two query shapes:

- **CVE-scoped** — `cves` present (explicit or SBOM-derived). Returns statements for those CVEs, optionally narrowed by `products` and the other filters. Classic behaviour.
- **Broad mode** — `cves` absent but `products`/components present. Returns **every** vendor statement touching the matched products, with no CVE filter. The result does not depend on which CVEs a given scan surfaced, because `trivy --vex` does its own CVE matching against the returned document — so one broad-mode document can be cached and reused across scans of the same image. Capped (see below).

Replaces the v0.3.0 trio (`GET /v1/cve/{id}`, `GET /v1/cve/{id}/summary`, `POST /v1/resolve`). All three paths now return `404`; migrate to `POST /v1/statements`.

### Request

```json
POST /v1/statements
{
  "cves":           ["CVE-2021-44228"],                                       // optional if products/sbom present (broad mode)
  "products":       ["pkg:rpm/redhat/log4j@2.14.0?repository_id=rhel-8-..."], // optional
  "sbom":           { /* CycloneDX 1.4+ */ },                                  // optional
  "vendors":        ["redhat", "suse"],                                        // optional
  "source_formats": ["csaf"],                                                  // optional
  "statuses":       ["not_affected", "fixed"],                                 // optional
  "justifications": ["vulnerable_code_not_present"],                           // optional
  "scopes":         ["pkg:oci/longhorn-engine?repository_url=..."],            // optional; opts in product-scoped statements (Rancher VEX)
  "strict_arch":    false,                                                     // optional; narrow to the architectures the products name
  "since":          "2026-01-01T00:00:00Z",                                    // optional, RFC3339
  "limit":          50000,                                                     // optional, clamped to server -statements-max
  "offset":         0                                                          // optional, for paging a truncated result
}
```

### Filter semantics

- **AND** across populated dimensions, **IN** within each non-empty list. So `vendors: [a, b]` AND `statuses: [c, d]` reads as `(vendor IN (a, b)) AND (status IN (c, d))`.
- An empty list (or omitted field) means "no filter on that dimension."
- **At least one of `cves`, `products`, or `sbom` is required.** With no CVEs but products/components present, the query runs in broad mode (all CVEs for the matched products). Only a request with neither CVEs nor products → 400 with `one of cves, products, or sbom (with components or vulnerabilities) is required`. (Earlier versions required a CVE on the theory that vex-hub returns "vendor opinions about CVEs, not all-CVEs-on-a-product"; broad mode supersedes that — the product-scoped doc is the natural unit for `trivy --vex`, which matches CVEs itself.)
- `cves` and `products` are each capped at 10 000 entries.
- `since` filters by the statement's `updated` timestamp (`updated >= since`). RFC3339 string ordering matches chronological ordering, so e.g. `2026-04-01T00:00:00Z` returns rows updated on or after April 1, 2026.

### SBOM input

When `sbom` is present, reel-vex extracts:

- **CVEs** from `.vulnerabilities[].id`,
- **Products** from `.components[].purl` and `.components[].cpe`,
- **Scope** from `.metadata.component` (the SBOM's root subject) — opts in any product-scoped statements for that image/module (see [Product-scoped statements](#product-scoped-statements)).

Both sets are unioned with any explicit `cves` / `products` the request also carries — so a caller can broaden the query with extras without losing what the SBOM declared. The SBOM body counts against the same body-size cap as `/v1/analyze` (default 10 MB, configurable on the operator side via `-sbom-max-mb`).

So the `trivy image --vex` flow needs no `jq` extraction step — the Trivy JSON can be piped in as-is. See [recipes](#recipes) below.

### Resolver behaviour with `products`

When `products` is provided, each identifier runs through the resolver (`direct` / `via_alias` / `via_cpe_prefix` expansion) before matching, and the OpenVEX encoder echoes the user's input PURL into each statement's `products[]` so Trivy can match it.

When `products` is absent, no expansion happens and the encoder emits each statement's stored `product_id` (which may be a CPE for OVAL-derived rows). Trivy will ignore CPE-only entries; `vexctl` and other consumers accept them.

### Architecture matching (`strict_arch`)

**Added in 0.12.0.** Off by default; the default behaviour is unchanged.

Matching normally ignores the `arch` qualifier entirely (see [PURL identity rules](#purl-identity-rules)). That is the right default across a corpus where most feeds never qualify — but it means a scanner running on `amd64` gets `arm64` and `s390x` verdicts echoed back under its own identifier, with nothing in the response to say so.

Set `"strict_arch": true` and a statement row is returned only when it:

- carries no `arch` qualifier, **or**
- carries an architecture-independent one — `noarch`, `src`, `source`, `all` — which hold everywhere and are never narrowed away, **or**
- carries an architecture named by the request's own `products`.

Notes on the semantics:

- **The architecture set is request-level**, the union across every identifier supplied. A mixed-architecture request widens rather than narrows — the safe direction, and in practice one image is one architecture.
- **It is a no-op when no supplied identifier names an architecture**, including every CVE-only query. There is nothing to be strict about, so nothing is filtered.
- **Narrowing is never silent**: the response carries `X-Reel-Arch` with the set applied. There is no dropped-row count, because computing one would require running the un-narrowed query too.
- On `/v1/analyze` the architectures come from the SBOM's own components. Inbound `user_vex` is never narrowed: it asserts on a specific identifier, which reel-vex takes as given.

```json
{"cves": ["CVE-2019-9923"], "products": ["pkg:deb/ubuntu/tar@1.34-1?arch=amd64&distro=ubuntu-22.04"], "strict_arch": true}
```

### Cap, truncation, and ordering

- Results are capped at the server's `-statements-max` (default **50 000**; `0` = unlimited). A request `limit` lowers — never raises — that ceiling.
- **If the cap is hit, the response stays `200 OK`** with header **`X-Reel-Truncated: true`** and **`X-Reel-Next-Offset: <n>`**; pass that value back as `offset` to fetch the next page. Truncation is signalled only via headers — the OpenVEX body stays schema-valid (no custom fields), and the status stays 200 (an unsolicited 206 without `Content-Range` would violate RFC 7233 and can trip strict consumers/proxies). A truncated doc is genuinely incomplete: any statement it drops is a CVE `trivy --vex` won't suppress, so always check for `X-Reel-Truncated` when relying on broad mode for suppression.
- Statements are returned in a deterministic order (`base_id`, `cve`, `product_id`, `source_format`). The doc is byte-identical across refetches when the underlying data hasn't changed — so a cached/attached broad-mode doc is content-addressable and diff-friendly.

### Compression

Responses are gzip-compressed when the request sends `Accept-Encoding: gzip`. OpenVEX is highly repetitive and compresses ~10×, which keeps a large broad-mode doc small enough to cache and ship cheaply.

### Response headers

| Header | Meaning |
|---|---|
| `X-Reel-Mode` | `cve` or `broad` — which query shape ran. |
| `X-Reel-Statements` | Database rows matched. Unchanged by grouping. |
| `X-Reel-Grouped` | Statements actually emitted, i.e. `statements[]` length. ≤ `X-Reel-Statements`. |
| `X-Reel-CVE` | Echoes the queried CVE on single-CVE lookups. |
| `X-Reel-Arch` | Comma-separated architectures `strict_arch` applied. Absent when nothing was narrowed. |
| `X-Reel-Truncated` / `X-Reel-Next-Offset` | The result hit the cap; page with `offset`. |

All are exposed via CORS (`Access-Control-Expose-Headers`), so browser clients can read them.

### Response

`200 OK` with an OpenVEX 0.2.0 document; `204 No Content` if no statements matched.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-...",
  "author": "reel-vex aggregator <vex@getreel.dev>",
  "role": "aggregator",
  "timestamp": "2026-04-27T12:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2021-44228"},
      "timestamp": "2026-04-01T16:43:13Z",
      "products": [
        {"@id": "pkg:rpm/redhat/log4j", "identifiers": {"purl": "pkg:rpm/redhat/log4j"}},
        {"@id": "pkg:rpm/redhat/log4j-jcl", "identifiers": {"purl": "pkg:rpm/redhat/log4j-jcl"}}
      ],
      "status": "not_affected",
      "status_notes": "source_format=csaf; match_reason=via_alias",
      "justification": "vulnerable_code_not_present",
      "supplier": "redhat"
    }
  ]
}
```

### Common shapes

- **CVE-only lookup** (replaces `GET /v1/cve/{id}`):
  ```json
  {"cves": ["CVE-2021-44228"]}
  ```
- **Broad mode — all statements for an image's products**:
  ```json
  {"products": ["pkg:deb/ubuntu/openssl?distro=ubuntu-22.04", "pkg:deb/ubuntu/glibc?distro=ubuntu-22.04"]}
  ```
- **CVE × product matrix** (replaces `POST /v1/resolve`):
  ```json
  {"cves": ["CVE-..."], "products": ["pkg:..."]}
  ```
- **Filter to one vendor**:
  ```json
  {"cves": ["CVE-..."], "vendors": ["redhat"]}
  ```
- **Only "fixed" rows since a date** (incremental sync from a downstream cache):
  ```json
  {"cves": ["..."], "statuses": ["fixed"], "since": "2026-04-01T00:00:00Z"}
  ```

### What Trivy will and won't match

Trivy's `--vex` implementation matches on **PURL only** — it ignores `identifiers.cpe23` even when set. The encoder takes that into account by emitting the request's input PURLs (not the vendor's underlying CPEs) in `products[]` whenever `products` is provided. Trade-offs:

- Query with a PURL → hierarchical PURL in the doc → Trivy suppresses matching scan findings. ✓
- CVE-only query (no `products`) → `products[]` carries each statement's stored identifier, which may be CPE → Trivy ignores. Use `vexctl` or any other OpenVEX consumer instead, or add `products` to the request.
- Multi-product statements (see [grouping](#statements-are-grouped-by-assertion-not-by-database-row)) are matched correctly — Trivy iterates `products[]`. Verified against Trivy 0.74.0: a grouped document suppresses the identical set of CVEs as the ungrouped equivalent, including with statements carrying thousands of products.

## Recipes

### Suppress vendor-acknowledged CVEs in a Trivy scan (SBOM passthrough)

Trivy's own CycloneDX output can be POSTed unchanged; the server extracts the CVEs and PURLs from it.

```bash
# 1. Trivy emits CycloneDX with .vulnerabilities[] populated.
trivy image --format cyclonedx --scanners vuln myimage:tag > sbom.json

# 2. POST it as-is; reel-vex pulls CVEs from .vulnerabilities[].id and
#    products from .components[].purl, then returns OpenVEX 0.2.0.
curl -s -X POST https://vex.getreel.dev/v1/statements \
  -H "Content-Type: application/json" \
  -d "$(jq -n --argjson sbom "$(cat sbom.json)" '{sbom: $sbom}')" > vex.json

# 3. Re-scan with the VEX doc applied; Trivy suppresses not_affected + fixed.
trivy image --vex vex.json myimage:tag
```

For `trivy sbom --vex`, swap `/v1/statements` for `/v1/analyze` and feed the returned annotated CycloneDX (with BOM-Link refs) to `--vex` instead.

### Query explicit CVE / PURL lists

When CVE and PURL lists already exist — extracted by another tool, or narrowed to a subset of an image's findings — skip the SBOM and pass them directly:

```bash
curl -s -X POST https://vex.getreel.dev/v1/statements \
  -H "Content-Type: application/json" \
  -d '{
    "cves":     ["CVE-2021-44228"],
    "products": ["pkg:rpm/redhat/log4j@2.14.0?repository_id=rhel-8-for-x86_64-appstream-rpms"]
  }'
```

`cves` and `products` may also be combined with `sbom` — the union of all three is queried.

### Layer user VEX on top of vendor data

A user VEX document (e.g. `vexctl create` output) describing application-layer assertions can be merged with vendor data by passing both through `/v1/analyze` in one call:

```bash
jq -n \
  --argjson sbom "$(cat sbom.json)" \
  --argjson vex  "$(cat my-vex.json)" \
  '{sbom: $sbom, user_vex: [$vex]}' | \
curl -X POST https://vex.getreel.dev/v1/analyze \
  -H "Content-Type: application/json" \
  -d @- > annotated.json
```

The annotated CycloneDX output reflects vendor + user merged with user override on collision.

### Diagnose why a statement matched

OpenVEX `status_notes` carries `source_format=` and `match_reason=` so consumers can see which feed produced a row and which rule fired:

```bash
curl -X POST https://vex.getreel.dev/v1/statements \
  -H "Content-Type: application/json" \
  -d '{"cves": ["CVE-2021-44228"], "products": ["pkg:rpm/redhat/log4j?repository_id=rhel-8-for-x86_64-appstream-rpms"]}' \
  | jq '.statements[].status_notes'
```

`match_reason=via_alias` confirms the repository-id qualifier expanded through reel-vex's alias table to reach a CPE-keyed statement. `match_reason=from_user_vex` confirms the row came from the request's `user_vex` payload.
