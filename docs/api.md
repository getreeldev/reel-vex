# reel-vex API reference

Canonical reference for every HTTP endpoint and response field. The live service is at `https://vex.getreel.dev`; the same binary powers any self-hosted deployment.

- [Endpoints](#endpoints)
- [Native response format](#native-response-format)
- [OpenVEX output format (opt-in)](#openvex-output-format-opt-in)
- [Recipes](#recipes)

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/v1/cve/{id}` | All statements for one CVE. |
| `GET`  | `/v1/cve/{id}/summary` | Counts + vendor list for one CVE. |
| `POST` | `/v1/resolve` | Batch query: CVEs × products → matching statements. Supports `"format": "openvex"`. |
| `POST` | `/v1/sbom` | Annotate a CycloneDX SBOM with VEX analysis. |
| `GET`  | `/v1/stats` | Coverage statistics. |
| `GET`  | `/v1/ingest` | Current ingest status. |
| `POST` | `/v1/ingest` | Trigger a manual ingest (admin token). |
| `GET`  | `/healthz` | Liveness probe. |

`/v1/resolve` is the endpoint most consumers use; the rest exists for inspection and health.

## Native response format

Every statement-returning endpoint (`/v1/cve/{id}`, `/v1/resolve`) emits the same statement object under `statements[]`. This is the reel-vex-native format — default, stable, and the only place `match_reason` and per-statement `source_format` are preserved.

### Field reference

| Field | Type | Always present? | Description |
|---|---|---|---|
| `vendor` | string | yes | Vendor identifier (e.g. `redhat`, `suse`). Matches the adapter ID that produced the statement. |
| `cve` | string | yes | CVE identifier. |
| `product_id` | string | yes | Full product identifier as published by the vendor — PURL (with version) or CPE 2.2 URI. |
| `version` | string | optional | Package version for PURL-keyed statements; omitted for CPE and for PURLs that were published without a version. |
| `id_type` | string | yes | `purl` or `cpe`. |
| `status` | string | yes | One of the four VEX statuses — see [Status values](#status-values). |
| `justification` | string | only on `not_affected` | One of five justification codes — see [Justification values](#justification-values). |
| `updated` | RFC3339 string | yes | Timestamp the vendor last updated this statement. |
| `source_format` | string | yes | Which upstream feed format carried this statement: `csaf` or `oval`. |
| `match_reason` | string | only on `/v1/resolve` and `/v1/sbom` | Why this row matched the query — `direct`, `via_alias`, or `via_cpe_prefix`. See [Match reasons](#match-reasons). |

### Status values

| Value | Meaning |
|---|---|
| `not_affected` | The vendor has confirmed this product is not impacted by the CVE. Usually paired with a `justification`. |
| `affected` | The vendor has confirmed this product is impacted. |
| `fixed` | A fix is available; consumers should upgrade. |
| `under_investigation` | Vendor has not yet determined impact. |

### Justification values

Only meaningful when `status == "not_affected"`. Values match the OpenVEX 0.2.0 enum, so they pass through to OpenVEX output unchanged.

| Value | Meaning |
|---|---|
| `component_not_present` | The vulnerable component isn't in the product at all. |
| `vulnerable_code_not_present` | The component is present, but the vulnerable code path isn't built in. |
| `vulnerable_code_not_in_execute_path` | Code is present but unreachable in this configuration. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | Code is reachable but an attacker can't reach the trigger condition. |
| `inline_mitigations_already_exist` | Runtime mitigation neutralises the vulnerability. |

### Match reasons

Returned only for endpoints that perform product expansion (`/v1/resolve`, `/v1/sbom`). Tells you which rule caused this statement to match your query.

| Value | Meaning | Precedence |
|---|---|---|
| `direct` | The query's normalised base identifier equals the statement's `base_id`. | 1 (strongest) |
| `via_alias` | The query carried a `?repository_id=X` PURL qualifier, and reel-vex's alias table maps that repository ID to a CPE that matches the statement. | 2 |
| `via_cpe_prefix` | The query is a CPE 2.2 URI, and its 5-part prefix (`part:vendor:product:version:update`) matches the statement — implements Red Hat's [SECDATA-1220](https://redhat.atlassian.net/browse/SECDATA-1220) contract. | 3 |

Precedence: when the same candidate is produced by multiple rules, the strongest reason wins.

### Source format filter

`/v1/resolve` accepts an optional `source_formats` array to restrict matches to specific upstream formats. Example — CSAF-only:

```json
{
  "cves": ["CVE-2025-2487"],
  "products": ["pkg:rpm/redhat/kernel?repository_id=rhel-9-for-x86_64-baseos-rpms"],
  "source_formats": ["csaf"]
}
```

Omit the field (or pass an empty list) to match every format.

### Example — `/v1/resolve` native

```bash
curl -X POST https://vex.getreel.dev/v1/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "cves": ["CVE-2021-44228"],
    "products": ["pkg:rpm/redhat/log4j@2.14.0?repository_id=rhel-8-for-x86_64-appstream-rpms"]
  }'
```

```json
{
  "statements": [
    {
      "vendor": "redhat",
      "cve": "CVE-2021-44228",
      "product_id": "cpe:/a:redhat:enterprise_linux:8::appstream",
      "id_type": "cpe",
      "status": "not_affected",
      "justification": "vulnerable_code_not_present",
      "updated": "2026-04-01T16:43:13Z",
      "source_format": "csaf",
      "match_reason": "via_alias"
    }
  ]
}
```

## OpenVEX output format (opt-in)

`/v1/resolve` emits an [OpenVEX 0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) document when the request body includes `"format": "openvex"`. Designed for drop-in consumption by [`vexctl`](https://github.com/openvex/vexctl) and Trivy's `--vex` flag.

```bash
curl -X POST https://vex.getreel.dev/v1/resolve \
  -H "Content-Type: application/json" \
  -d '{
    "cves": ["CVE-2021-44228"],
    "products": ["pkg:rpm/redhat/log4j@2.14.0?repository_id=rhel-8-for-x86_64-appstream-rpms"],
    "format": "openvex"
  }'
```

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-…",
  "author": "reel-vex aggregator <vex@getreel.dev>",
  "role": "aggregator",
  "timestamp": "2026-04-21T12:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2021-44228"},
      "timestamp": "2026-04-01T16:43:13Z",
      "products": [
        {
          "@id": "pkg:rpm/redhat/log4j",
          "identifiers": {"purl": "pkg:rpm/redhat/log4j"}
        }
      ],
      "status": "not_affected",
      "status_notes": "source_format=csaf; match_reason=via_alias",
      "justification": "vulnerable_code_not_present",
      "supplier": "redhat"
    }
  ]
}
```

### Design notes

- **Products echo your input.** Every user-supplied PURL in the request is normalised to its hierarchical base (no version, no qualifiers) and placed in each matched statement's `products[]`. That's the form Trivy's `--vex` matches against. A statement originally keyed to a CPE (Red Hat OVAL) still lands with your PURL in its `products[]` as long as the CPE and PURL resolve together via our alias table.
- **Vendor and diagnostics are preserved.** `supplier` carries the vendor; `status_notes` carries `source_format` and `match_reason` (e.g. `"source_format=csaf; match_reason=via_alias"`). Free-text fields the OpenVEX spec reserves for exactly this kind of traceability.
- **Determinism.** `@id` is a SHA-256 hash of the document body (ignoring timestamps); the same query produces the same `@id` byte-for-byte. Good for caching.
- **Empty results return `204 No Content`** — the OpenVEX schema requires at least one statement, so we return nothing rather than emit an invalid doc.
- **No signing (yet).** `author` is a literal string identifying reel-vex as an aggregator; we don't sign documents today. Signed attestations are planned as a future deliverable.

### What Trivy will and won't match

Trivy's `--vex` implementation matches on **PURL only** — it ignores `identifiers.cpe23` even when set. Our encoder takes that into account by emitting your input PURLs (not the vendor's underlying CPEs) in `products[]`. Trade-offs:

- Query with a PURL → hierarchical PURL in the doc → Trivy suppresses matching scan findings. ✓
- Query with only a CPE → CPE-only `products[]` → Trivy ignores, though `vexctl` and other OpenVEX consumers still accept the doc.

## Recipes

### Query one CVE for one image

```bash
# 1. Extract the PURLs + CVEs Trivy sees in your image.
trivy image --format json myimage:tag > scan.json
PURLS=$(jq -r '.Results[].Vulnerabilities[]?.PkgRef' scan.json | sort -u)
CVES=$(jq -r '.Results[].Vulnerabilities[].VulnerabilityID' scan.json | sort -u)

# 2. Ask reel-vex which ones the vendor says don't apply.
curl -s -X POST https://vex.getreel.dev/v1/resolve \
  -H "Content-Type: application/json" \
  -d "$(jq -n --argjson cves "$(echo "$CVES" | jq -R . | jq -s .)" \
               --argjson purls "$(echo "$PURLS" | jq -R . | jq -s .)" \
              '{cves: $cves, products: $purls, format: "openvex"}')" > vex.json

# 3. Re-scan with the VEX doc applied; Trivy suppresses not_affected + fixed.
trivy image --vex vex.json myimage:tag
```

### Gate pipelines with a specific format

If your gating tooling consumes OpenVEX only, you never want to see the native format. Always pass `"format": "openvex"` in the POST body — it's additive and ignored by older clients.

### Diagnose why a statement matched

Drop `format` to get the native response with `match_reason`. Useful when debugging why a CPE-only statement was returned for a PURL query, or vice versa.

```bash
curl -X POST https://vex.getreel.dev/v1/resolve \
  -H "Content-Type: application/json" \
  -d '{"cves": ["CVE-2021-44228"], "products": ["pkg:rpm/redhat/log4j?repository_id=rhel-8-for-x86_64-appstream-rpms"]}'
```

`match_reason: via_alias` confirms the repository-id qualifier expanded through reel-vex's alias table to reach a CPE-keyed statement.
