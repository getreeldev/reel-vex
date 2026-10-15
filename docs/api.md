# reel-vex API reference

reel-vex answers one question: **for these packages, what did the vendor say about these CVEs?** Vendors publish those answers as VEX (Vulnerability Exploitability eXchange): a verdict per CVE and product, such as `not_affected` or `fixed`. reel-vex collects them from nine vendors and serves them over HTTP. The public instance is `https://vex.getreel.dev`, free and without authentication. A self-hosted server runs the same binary.

Packages are named by PURL (Package URL, e.g. `pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12`) or by CPE (Common Platform Enumeration, e.g. `cpe:/o:redhat:enterprise_linux:8`).

| Method | Path | Use it to |
|---|---|---|
| `POST` | [`/v1/statements`](#post-v1statements) | Get vendor statements as an OpenVEX document, from CVE and package lists or a CycloneDX SBOM. Pair with `trivy image --vex`. |
| `POST` | [`/v1/analyze`](#post-v1analyze) | Get a CycloneDX SBOM back with each vulnerability annotated, and merge your own VEX on top. Pair with `trivy sbom --vex`. |
| `GET` | [`/v1/stats`](#get-v1stats) | Coverage counts. |
| `GET` | [`/v1/ingest`](#get-v1ingest-and-post-v1ingest) | Ingest status. `POST` starts one (admin). |
| `GET` | [`/healthz`](#get-healthz) | Health check, including the database. |

- [Quick recipes](#quick-recipes)
- [Response format](#response-format)
- [Versioned queries](#versioned-queries) · [Product-scoped statements](#product-scoped-statements) · [Debian source packages](#debian-source-packages) · [PURL identity rules](#purl-identity-rules)

## Quick recipes

Every recipe below was run against the live hub with Trivy 0.74.0.

### Hide vendor-cleared findings in `trivy image`

Scan once to get an SBOM, send it to reel-vex, then scan again with the answer as VEX:

```bash
IMAGE=registry.access.redhat.com/ubi9-minimal
trivy image --format cyclonedx --scanners vuln "$IMAGE" > sbom.json
jq '{sbom: .}' sbom.json | curl -s https://vex.getreel.dev/v1/statements \
  -H 'Content-Type: application/json' -d @- > vex.json
trivy image --vex vex.json "$IMAGE"
```

Trivy hides the findings a vendor marked `not_affected` or `fixed` (10 of 180 on this image when this was written).

If no vendor said anything, the hub answers `204 No Content` and `vex.json` is empty. Trivy then stops with `unable to decode VEX`. Check the status code before passing `--vex`:

```bash
code=$(jq '{sbom: .}' sbom.json | curl -s -o vex.json -w '%{http_code}' \
  https://vex.getreel.dev/v1/statements -H 'Content-Type: application/json' -d @-)
if [ "$code" = 200 ]; then trivy image --vex vex.json "$IMAGE"; else trivy image "$IMAGE"; fi
```

### Annotate an SBOM for `trivy sbom`

`/v1/analyze` returns your SBOM with an `analysis` on each vulnerability, linked to its components the way `trivy sbom --vex` expects:

```bash
jq '{sbom: .}' sbom.json | curl -s https://vex.getreel.dev/v1/analyze \
  -H 'Content-Type: application/json' -d @- > annotated.json
trivy sbom --vex annotated.json sbom.json
```

This route can hide more findings than `/v1/statements`. Where a package's vendor rows disagree, the annotation takes the most favourable verdict. See [Annotation](#annotation).

### Ask about specific CVEs and packages

Skip the SBOM and send lists:

```bash
curl -s https://vex.getreel.dev/v1/statements -H 'Content-Type: application/json' \
  -d '{"cves": ["CVE-2022-37434"],
       "products": ["pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12"]}'
```

Debian says `fixed`. With a version in the PURL, you only get verdicts that hold for that version. See [Versioned queries](#versioned-queries).

### Add your own VEX

Send your own OpenVEX (for example from `vexctl create`) with the SBOM. Your statement replaces the vendor's for the same CVE and package:

```bash
cat > my-vex.json <<'EOF'
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [{
    "vulnerability": {"name": "CVE-2021-46195"},
    "products": [{"@id": "pkg:rpm/redhat/libgcc"}],
    "status": "affected",
    "supplier": "acme"
  }]
}
EOF
jq -n --slurpfile sbom sbom.json --slurpfile vex my-vex.json \
  '{sbom: $sbom[0], user_vex: $vex}' |
curl -s https://vex.getreel.dev/v1/analyze -H 'Content-Type: application/json' -d @- > annotated.json
```

On the ubi9-minimal SBOM, CVE-2021-46195 is `not_affected` from Red Hat alone. With this file it becomes `exploitable`, with the detail `acme: affected`.

### See why a statement matched

Each statement's `status_notes` names the feed format and the matching rule:

```bash
curl -s https://vex.getreel.dev/v1/statements -H 'Content-Type: application/json' \
  -d '{"cves": ["CVE-2022-3602"],
       "products": ["pkg:rpm/redhat/openssl?repository_id=rhel-8-for-x86_64-baseos-rpms"]}' |
jq -r '.statements[] | "\(.status)  \(.status_notes)"'
```

```
not_affected  source_format=csaf; match_reason=via_alias
not_affected  source_format=csaf; match_reason=direct
fixed  source_format=csaf; match_reason=direct
```

`via_alias` means the `repository_id` was translated to a Red Hat product CPE, which carries a verdict for RHEL 8 as a whole. The two `direct` statements are about the `openssl` package itself. Red Hat states them per product stream, so one package can get both `not_affected` and `fixed`. See [Match reasons](#match-reasons).

## Response format

`/v1/statements`, and `/v1/analyze` when it gets only `user_vex`, return an [OpenVEX 0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) document. There is no other format.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-c30ea539…",
  "author": "reel-vex aggregator <vex@getreel.dev>",
  "role": "aggregator",
  "timestamp": "2026-10-15T23:30:16Z",
  "version": 1,
  "statements": [{
    "timestamp": "2026-10-04T23:26:37Z",
    "vulnerability": {"name": "CVE-2022-37434"},
    "products": [{
      "@id": "pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12",
      "identifiers": {"purl": "pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12"}
    }],
    "status": "fixed",
    "status_notes": "source_format=oval; match_reason=direct",
    "supplier": "debian"
  }]
}
```

**No match is `204 No Content`** with an empty body. OpenVEX requires at least one statement, so an empty document would be invalid.

**One statement can name many products.** Rows that agree on every statement field (CVE, status, justification, supplier, timestamp and `status_notes`) are sent once, with all their products in `products[]`. Rows that differ on any of them stay separate statements, so a CSAF row and an OVAL row are never merged. Always iterate the whole `products[]`.

### Fields

| Field | What it holds |
|---|---|
| `@id` | A hash of the document's content. The same query on the same data gives the same `@id`. |
| `timestamp` (document) | When this response was made. It changes on every call. |
| `author`, `role`, `version` | Always `reel-vex aggregator <vex@getreel.dev>`, `aggregator` and `1`. Documents are not signed. |
| `statements[].vulnerability.name` | The CVE id. |
| `statements[].products[]` | What the statement is about. A PURL is in both `@id` and `identifiers.purl`. A CPE is in `identifiers.cpe23` only, written as stored. Which identifier you get back is explained under [`POST /v1/statements`](#which-identifiers-come-back). |
| `statements[].status` | `not_affected`, `affected`, `fixed` or `under_investigation`. |
| `statements[].justification` | Why it is `not_affected`, when the vendor said. |
| `statements[].impact_statement` | Set on a `not_affected` with no justification: `Not affected per vendor statement; no justification supplied.` |
| `statements[].action_statement` | Set on every `affected`: `Follow vendor advisory for remediation.` |
| `statements[].status_notes` | Provenance, see below. |
| `statements[].supplier` | The vendor: `redhat`, `suse`, `rancher`, `ubuntu`, `debian`, `alpine`, `amazon`, `almalinux` or `oracle`. For your own VEX, the `supplier` you sent. |
| `statements[].timestamp` | When the vendor last updated this verdict. |

**Every status the vendor stated is returned**, including `affected` and `under_investigation`. Trivy acts on `not_affected` and `fixed` and ignores the other two. Other tools may differ. Filter with `statuses` if you want fewer.

Justifications are the OpenVEX five: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.

### `status_notes`

A `; `-separated list of `key=value` pairs:

| Key | Values | When |
|---|---|---|
| `source_format` | `csaf`, `oval`, `openvex`, `secdb`, `updateinfo` | Every vendor statement. Absent on your own VEX. |
| `match_reason` | see [Match reasons](#match-reasons) | Only when the request named products (or sent an SBOM or user VEX). |
| `scope` | the image or module the verdict is about | [Product-scoped](#product-scoped-statements) statements only. |
| `converted_from`, `original_state`, `original_justification`, `fidelity` | e.g. `converted_from=cyclonedx-vex; original_state=not_affected; original_justification=code_not_reachable; fidelity=exact` | Your own VEX, when it was converted from CycloneDX. |

### Match reasons

| `match_reason` | The statement matched because |
|---|---|
| `from_user_vex` | it is your own statement, from `user_vex` on `/v1/analyze`. It overrides vendor rows. |
| `direct` | its package is the one you named (version and filter qualifiers aside). |
| `via_alias` | your PURL's `repository_id` maps to a Red Hat CPE that the statement is about. |
| `via_cpe_prefix` | you sent a CPE 2.2 URI and its first five parts (`part:vendor:product:version:update`) match the statement's. This follows Red Hat's [SECDATA-1220](https://redhat.atlassian.net/browse/SECDATA-1220). |
| `via_source_package` | SBOM input only: the statement is about the Debian source package your component was built from. See [Debian source packages](#debian-source-packages). |

When several rules reach the same statement, the strongest is reported, in the order of this table.

## POST /v1/statements

Send CVEs, packages, a CycloneDX SBOM, or any mix. Get back the matching vendor statements as OpenVEX.

```bash
curl -s https://vex.getreel.dev/v1/statements -H 'Content-Type: application/json' \
  -d '{"cves": ["CVE-2021-44228"],
       "products": ["pkg:rpm/redhat/log4j?repository_id=rhel-8-for-x86_64-appstream-rpms"]}'
```

The answer is one Red Hat statement: `not_affected`, `vulnerable_code_not_present`, product `pkg:rpm/redhat/log4j`.

### Request

| Field | Type | Meaning |
|---|---|---|
| `cves` | string[] | CVE ids. |
| `products` | string[] | PURLs or CPEs. |
| `sbom` | object | A CycloneDX 1.4+ SBOM, inline. See [SBOM input](#sbom-input). |
| `vendors` | string[] | Keep only these suppliers. |
| `source_formats` | string[] | Keep only these feed formats (`csaf`, `oval`, …). |
| `statuses` | string[] | Keep only these statuses. |
| `justifications` | string[] | Keep only these justifications. |
| `scopes` | string[] | Images or modules you are scanning. Opts in [product-scoped statements](#product-scoped-statements). |
| `strict_arch` | bool | Drop other architectures' statements. See [`strict_arch`](#strict_arch). Default `false`. |
| `since` | RFC 3339 string | Keep statements the vendor updated at or after this time. |
| `limit` | int | Page size. Can only lower the server's cap. |
| `offset` | int | Rows to skip, for [paging](#paging-and-truncation). |

You need at least one of `cves`, `products` or `sbom`. Otherwise the answer is `400` with `one of cves, products, or sbom (with components or vulnerabilities) is required`.

**Filters combine with AND, values inside one filter with OR.** `{"vendors": ["redhat", "suse"], "statuses": ["fixed"]}` means (Red Hat or SUSE) and `fixed`. An empty or missing field filters nothing.

**Without `cves`, you get every statement for the packages** (broad mode). This is the usual way to fetch VEX for an image: the answer does not depend on which CVEs one scan found, because Trivy matches CVEs itself. So one document can be cached and reused for every scan of the same image. Broad mode is capped like any query: check [`X-Reel-Truncated`](#paging-and-truncation).

**With `cves` and no `products`**, you get every statement for those CVEs, under each vendor's own identifiers. Those are often CPEs, which Trivy ignores.

### SBOM input

From `sbom`, reel-vex reads:

- **CVEs** from `vulnerabilities[].id`,
- **packages** from the top-level `components[].purl` and `components[].cpe`, plus the [Debian source package](#debian-source-packages) Trivy records on a component,
- **the scope** from `metadata.component`, which opts in [product-scoped statements](#product-scoped-statements) for that image.

These are added to any `cves`, `products` and `scopes` you also send. Trivy's CycloneDX output can be sent unchanged. An SBOM with no vulnerabilities, sent without `cves`, runs in broad mode.

### Which identifiers come back

Trivy matches a statement to a finding by PURL. So when you name packages, the answer names them the way you did. **Base form** means no version and no qualifier except `distro`.

| Row kind | Named in `products[]` as |
|---|---|
| Most rows | your identifier in **base form**: no version, and no qualifier except `distro`, written as you wrote it. |
| [Fixed-in rows](#versioned-queries) (Debian, Ubuntu OVAL, AlmaLinux, Oracle, Alpine, Amazon), when your identifier has a version | your identifier **exactly as sent**, version and qualifiers included. |
| [Exact-list rows](#versioned-queries) (Ubuntu OpenVEX, Rancher) | the vendor's identifier, once per version that matched, written as Trivy writes it. |
| Any row, when the request named no products | the vendor's stored identifier, which may be a CPE. |

A Debian row reached through a source package is named by the binary you sent. A CPE you send is passed through as written.

### `strict_arch`

By default, matching ignores architecture. Feeds disagree on whether to state it at all, so exact matching would miss most verdicts. The cost is that an `amd64` scan also gets `arm64` and `s390x` statements, under its own identifier.

With `"strict_arch": true`, a row is kept only if its product has no `arch`, an architecture-independent one (`noarch`, `src`, `source`, `all`), or an `arch` one of your products names.

```bash
curl -s https://vex.getreel.dev/v1/statements -H 'Content-Type: application/json' \
  -d '{"cves": ["CVE-2022-37434"], "strict_arch": true,
       "products": ["pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04&epoch=1"]}'
```

Canonical's statement then names only the `amd64` build instead of seven architectures, and the response carries `X-Reel-Arch: amd64`.

- **The architecture set is the union over every product you send.** A mixed request widens rather than narrows.
- **No product with an `arch` means nothing is filtered**, which includes every CVE-only query.
- `X-Reel-Arch` says which architectures were applied. There is no count of what was dropped.

### Paging and truncation

The server returns at most `-statements-max` rows (default **50,000**, `0` = no cap). Your `limit` can lower that, never raise it.

When a result is cut, the status stays `200` and two headers say so:

```
X-Reel-Truncated: true
X-Reel-Next-Offset: 100
```

Send the same request again with `"offset": 100` for the next page. **A truncated document is incomplete.** Any statement it leaves out is a finding Trivy will not hide, so check this header whenever you rely on broad mode.

<details><summary>Paging details</summary>

- Rows come in a fixed order (`base_id`, `cve`, `product_id`, `source_format`, `vendor`, `scope`, `status`, `justification`), so pages never overlap or skip while the data is unchanged.
- Version selection runs before paging. `limit`, `offset` and the counts cover only rows that are returned.
- The `strict_arch` filter is checked once more after the page is cut. A narrowed page can hold fewer rows than `limit` and still be marked truncated.
- Within one document, statements are sorted by CVE, supplier, feed format and product.
</details>

### Compression

Send `Accept-Encoding: gzip` and the response is gzip-compressed. OpenVEX compresses about tenfold. A `204` is never compressed.

### Response headers

| Header | Meaning | Readable from a browser |
|---|---|---|
| `X-Reel-Mode` | `cve` or `broad`: which kind of query ran. | no |
| `X-Reel-Statements` | Rows in this answer (this page), after version selection and `strict_arch`. Not a total. | no |
| `X-Reel-Grouped` | Statements in the document after [grouping](#response-format). | yes |
| `X-Reel-CVE` | The CVE, when exactly one was asked about. | no |
| `X-Reel-Arch` | Architectures `strict_arch` applied. Absent when `strict_arch` is off or no product names an architecture. | yes |
| `X-Reel-Truncated`, `X-Reel-Next-Offset` | The result was cut. Page with `offset`. | yes |

"Readable from a browser" means the header is listed in `Access-Control-Expose-Headers`. The others are sent, but cross-origin JavaScript cannot read them.

### Errors

| Status | When |
|---|---|
| `400` | Invalid JSON or SBOM, no CVEs or products, more than 10,000 items in `cves` or `products` (counted after the SBOM is added), or an SBOM over the component or vulnerability limit (50,000 and 10,000). |
| `413` | Body over `-sbom-max-mb` (default 10 MB). A body sent without `Content-Length` that runs over gets `400 invalid JSON` instead. |
| `500` | `query failed`, including a query that ran past `-query-timeout` (default 20 s). |

Errors have a JSON body: `{"error": "<message>"}`.

### Common shapes

```jsonc
{"cves": ["CVE-2021-44228"]}                                         // every statement for a CVE
{"products": ["pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
              "pkg:deb/ubuntu/glibc?distro=ubuntu-22.04"]}           // broad mode
{"cves": ["CVE-2021-44228"], "vendors": ["redhat"]}                  // one vendor
{"cves": ["CVE-2024-6387"], "statuses": ["fixed"],
 "since": "2026-01-01T00:00:00Z"}                                    // recent fixes only
```

### What Trivy will and won't match

- **Trivy's `--vex` matches on PURL only** and ignores `identifiers.cpe23`. Name packages or send an SBOM, so every statement names your PURLs. A CVE-only answer often names CPEs, which only other OpenVEX consumers can use.
- **Statements with many products work.** Trivy checks every entry of `products[]`.
- **When the document holds both `affected` and `not_affected` for the same package**, as Red Hat's per-stream statements can, Trivy 0.74.0 keeps the finding.

## POST /v1/analyze

Send a CycloneDX SBOM, your own VEX, or both. With an SBOM you get the SBOM back, annotated. With only VEX you get OpenVEX back, merged with vendor data.

```bash
jq '{sbom: .}' sbom.json | curl -s https://vex.getreel.dev/v1/analyze \
  -H 'Content-Type: application/json' -d @- > annotated.json
```

### Request

| Field | Type | Meaning |
|---|---|---|
| `sbom` | object | A CycloneDX 1.4+ SBOM, inline. |
| `user_vex` | object[] | Up to 10 VEX documents: OpenVEX 0.2.0, or CycloneDX with VEX (converted on the way in). |
| `strict_arch` | bool | Narrow vendor rows to the architectures in the SBOM's components, as on [`/v1/statements`](#strict_arch). Your own VEX is never narrowed. |
| `reject_cyclonedx_lossy` | bool | Drop CycloneDX VEX statements that have no exact OpenVEX equivalent, instead of mapping them to the nearest value. Default `false`. |

You need `sbom` or `user_vex`. Otherwise the answer is `400` with `at least one of sbom or user_vex required`. The body is inline JSON. Multipart uploads are not accepted.

### What comes back

| You send | You get |
|---|---|
| `sbom` with `vulnerabilities[]` | The SBOM, with an `analysis` added to each vulnerability a vendor (or you) spoke about. No CVEs are added. |
| `sbom` with no or empty `vulnerabilities[]` | The SBOM, with `vulnerabilities[]` built from every vendor statement about its components, each annotated. See [broad mode](#broad-mode-sboms-without-vulnerabilities). |
| `user_vex` only | OpenVEX 0.2.0: your statements plus the vendor statements for the same CVEs and packages that yours do not override. `204` if none of your statements were valid. |
| both | The annotated SBOM, with your statements taking precedence. |

With an SBOM, the response is always `200` with the SBOM, even when nothing matched. Each `affects[].ref` that is a component's PURL is rewritten as a CycloneDX BOM-Link, `urn:cdx:<serialNumber>/<version>#<bom-ref>`. That link is how `trivy sbom --vex` ties the analysis to its findings. The `urn:uuid:` prefix is taken off `serialNumber`. If the SBOM has no `serialNumber`, or a ref matches no component with a `bom-ref`, that ref is left as it was. Trivy then cannot link that analysis to a finding and logs `Unable to parse BOM-Link`.

### Annotation

Each `analysis` has a `state`, a `detail` listing every statement that took part, and a `justification` when there is one:

```json
"analysis": {
  "state": "not_affected",
  "justification": "code_not_present",
  "detail": "redhat: affected; redhat: not_affected (vulnerable_code_not_present); …"
}
```

| OpenVEX status | CycloneDX `state` | Rank |
|---|---|---|
| `not_affected` | `not_affected` | 1 (wins) |
| `fixed` | `resolved` | 2 |
| `under_investigation` | `in_triage` | 3 |
| `affected` | `exploitable` | 4 |

**When the rows for one component disagree, the most favourable state wins**, by the rank above. Red Hat states verdicts per product stream and reel-vex cannot tell streams apart (see [Versioned queries](#versioned-queries)). So a package one stream calls `affected` and another calls `not_affected` is annotated `not_affected`. `/v1/statements` returns both and lets the consumer decide.

Justifications map as follows: `component_not_present` and `vulnerable_code_not_present` become `code_not_present`, `vulnerable_code_not_in_execute_path` becomes `code_not_reachable`, `inline_mitigations_already_exist` becomes `protected_by_mitigating_control`. `vulnerable_code_cannot_be_controlled_by_adversary` has no CycloneDX equivalent and is left out.

**Verdicts are judged per component.** A vulnerability's `affects[]` names components.

- Each component gets only the rows about it: an exact-list row only at a listed version, a fixed-in row only at or above the fix.
- The vulnerability is annotated only if **every** component it names has a verdict and they all agree on the state. Otherwise it is left as it came.
- The justification is kept only if they agree on that too.
- A vulnerability naming no component in the SBOM gets the verdict of all rows for its CVE.

Debian components are also looked up by their [source package](#debian-source-packages). [Product-scoped statements](#product-scoped-statements) apply when the SBOM's `metadata.component` is their scope.

### Broad mode: SBOMs without vulnerabilities

If `vulnerabilities[]` is missing or empty, reel-vex looks up every vendor statement about the SBOM's components, with no CVE filter. It then writes one vulnerability per CVE found, with `affects[]` naming the components the statements are about, and annotates each. One call turns a components-only SBOM into a VEX-annotated one.

An SBOM that already has vulnerabilities is never extended: you get analyses on what you sent, nothing more.

The lookup is capped at `-statements-max` rows (default 50,000). If the cap is hit, the response is still `200`, with `X-Reel-Truncated: true`, and some CVEs are missing. There is no offset here: send fewer components for complete coverage.

### User-VEX merge semantics

- **Your statement overrides the vendor's** when both are about the same CVE and the same package. Packages are compared in base form: no version, no qualifiers except `distro`. CPEs are compared as written.
- **One statement of yours about a CVE decides that CVE everywhere in the SBOM.** The annotation then uses only your statements for that CVE, on every component, even ones your statement doesn't name. Vendor rows for that CVE are ignored there, so a vendor `not_affected` can't outrank your `affected`.
- **Two of your statements on the same CVE and package**: the newer `timestamp` wins, and on a tie, the later one in the request.
- **Timestamps**: a statement without `timestamp` takes the document's. If both are missing or unreadable, it gets the time of the request. Set them yourself if you need stable output.
- Your statements carry `match_reason=from_user_vex` and your `supplier` as sent.
- **Vendor rows are narrowed by the SBOM's versions. Yours never are.**

**CycloneDX VEX is accepted** in `user_vex`. A document with `"bomFormat": "CycloneDX"` is converted to OpenVEX. CycloneDX words in an OpenVEX document are converted too: the justification `requires_environment` becomes `vulnerable_code_cannot_be_controlled_by_adversary`, flagged `fidelity=lossy`. A `false_positive` with no justification cannot become valid OpenVEX and is skipped. Each converted statement says so in `status_notes`. The `X-Reel-Converted` header counts what happened, for example `converted=1; lossy=0; contested=0; skipped=0`.

**A statement that is not valid OpenVEX is skipped, not refused.** That covers an unknown status or justification, `not_affected` with no justification, a justification on another status, and a product with no `@id`, `purl`, `cpe22` or `cpe23`. The rest of the request goes ahead, and `X-Reel-Converted` reports the count as `skipped=N`. Check that header if a statement seems to have had no effect.

**Your VEX is never stored or logged.** It is parsed, merged, returned and discarded. Only the counts in `X-Reel-Converted` leave the request.

### Limits and errors

| Rule | Limit | Status |
|---|---|---|
| Request body | 10 MB (`-sbom-max-mb`) | `413` |
| `user_vex` documents | 10 | `400` |
| Statements across all `user_vex` documents | 25,000 (`-max-user-vex-statements`) | `400` |
| Products in one statement | 100 | `400` |
| SBOM components | 50,000 (`-max-sbom-components`) | `400` |
| SBOM vulnerabilities | 10,000 (`-max-sbom-vulns`) | `400` |
| Distinct CVEs to look up (SBOM plus your VEX) | 10,000 (`-analyze-max-cves`) | `400` |
| `@context` must be exactly `https://openvex.dev/ns/v0.2.0` | | `422` |
| A `user_vex` document that cannot be read | | `422` |
| Lookup runs past `-query-timeout` (20 s) | | `503` |

### Response headers

`X-Reel-Mode` (`cve`, or `broad` when vulnerabilities were built), `X-Reel-Statements` (rows after the merge), `X-Reel-Arch`, `X-Reel-Truncated` and `X-Reel-Converted` mean what they do on [`/v1/statements`](#response-headers). `X-Reel-Grouped` is sent only on the OpenVEX answer.

## Versioned queries

Put a version in a PURL and you get only the verdicts that hold for that version. Leave it out and you get every verdict for the package.

What "holds for that version" means depends on how the vendor states versions:

| Feeds | The vendor states | A versioned query gets | Named in the answer as |
|---|---|---|---|
| Debian, Ubuntu OVAL, AlmaLinux, Oracle, Alpine, Amazon (**fixed-in**) | `fixed` in version X | `fixed` only if your version is X or later | your PURL exactly as sent |
| Ubuntu OpenVEX, Rancher (**exact-list**) | a verdict for listed builds | the verdict for your exact build, or nothing | the vendor's PURL at your version |
| Red Hat, SUSE (**version-blind**) | a verdict per product stream | every verdict, whatever the version | your PURL in base form |

A query **without a version** gets every verdict. A fixed-in row is then named by your base-form PURL. An exact-list row comes back once per listed build, each under its own versioned PURL.

### Example

CVE-2022-37434 in zlib. Debian fixed it in `1:1.2.11.dfsg-4.1` for bookworm. Canonical lists Ubuntu 22.04's `zlib1g` at `1:1.2.11.dfsg-2ubuntu9.2` as `fixed`.

| `products` | Answer |
|---|---|
| `pkg:deb/debian/zlib@1:1.2.11.dfsg-4.1?distro=debian-12` | `fixed` (Debian) |
| `pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12` | `fixed` (Debian): later than the fix |
| `pkg:deb/debian/zlib@1:1.2.11.dfsg-2?distro=debian-12` | `204`: earlier than the fix, still vulnerable |
| `pkg:deb/debian/zlib@1.2.13.dfsg-1?distro=debian-12` | `204`: no epoch means epoch 0, which is earlier than `1:` |
| `pkg:deb/debian/zlib@1.2.13.dfsg-1?distro=debian-12&epoch=1` | `fixed` (Debian) |
| `pkg:deb/debian/zlib?distro=debian-12` | `fixed` (Debian), named without a version |
| `pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04&epoch=1` | `fixed` twice: Canonical's OpenVEX lists this build, and Ubuntu OVAL's fix is reached |
| `pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.5?arch=amd64&distro=ubuntu-22.04&epoch=1` | `fixed` from Ubuntu OVAL only: Canonical never listed this build |
| `pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9?arch=amd64&distro=ubuntu-22.04&epoch=1` | `204` |

Each request was `{"cves": ["CVE-2022-37434"], "products": ["<the PURL>"]}`.

### Rules

- **Versions are compared as the package manager would** (dpkg for `deb`, rpm for `rpm`, apk for `apk`, using the libraries Trivy uses), but only for fixed-in rows. Exact-list rows need the exact version string, after the decoding below.
- **An epoch can be written either way.** `epoch=1` as a qualifier and `1:` in the version are the same. A version with neither has epoch 0.
- **Versions are percent-decoded first.** `%2B` is `+`, and a literal `+` is never read as a space.
- **Exact-list feeds are strict on purpose.** A new Ubuntu build that Canonical has not listed yet gets nothing from Canonical's OpenVEX until it does. That is the safe direction for `fixed`, but it can leave open a finding that a `not_affected` would have hidden.
- **Only `fixed` rows carry a fixed-in version.** Other verdicts from fixed-in feeds hold for every version: Debian's open CVEs (stated as `0:0`, served as `affected`) and Alpine's `"0"` (served as `not_affected`).
- **Red Hat and SUSE ignore the version.** Their verdicts hold per product stream, which reel-vex does not record, so they cannot be compared to a version. A RHEL 8 `openssl` query at any version gets the same answer.

<details><summary>Edge cases</summary>

- An exact-list row whose vendor gave no version at all (Rancher does this for every deb, rpm and apk subcomponent) matches any version and is named by the vendor's versionless PURL.
- Exact-list PURLs are written as Trivy writes them: for `deb` and `rpm`, an inline epoch moves to the `epoch` qualifier and the rest is percent-encoded. Canonical's `bind9` at `1:9.11.3+dfsg-1ubuntu1.18` comes back as `pkg:deb/ubuntu/bind9@9.11.3%2Bdfsg-1ubuntu1.18?arch=amd64&distro=ubuntu-18.04&epoch=1`. Other versions are written as the vendor wrote them.
- Each exact-list row is judged by its own list. A version listed for another CVE, architecture or scope never admits a different row.
- A package named both with and without a version in one request gets every verdict.
- If several of your products reach one fixed-in row, the answer names only those at or above the fix.
- A version the ordering cannot read gets no `fixed` from a fixed-in row.
- Where a feed states several fixed-in versions for one package and CVE (parallel kernel or module streams, two Amazon advisories), one is kept per row, and it may belong to another stream. A version below it then gets no `fixed`.
- Exact-list rows are never matched through a Debian source package. A fixed-in row reached through one is compared with the source package's version.
- Version selection happens before paging, so `limit`, `offset`, `X-Reel-Statements` and `X-Reel-Truncated` count only rows returned.
- On `/v1/analyze`, versions come from each SBOM component. Your own VEX is never narrowed by version, and a vendor row reached only through your statement's identifier keeps its whole version list.
</details>

## Product-scoped statements

Most feeds talk about packages. Rancher's VEX hub talks about a package **inside one image or Go module** (the scope): "zlib is `not_affected` in this image." reel-vex returns such a statement only when you name its scope. A verdict about one image never hides the same package in another.

```bash
curl -s https://vex.getreel.dev/v1/statements -H 'Content-Type: application/json' \
  -d '{"cves": ["CVE-2026-24061"],
       "products": ["pkg:deb/ubuntu/inetutils-ping?distro=ubuntu-22.04"],
       "scopes": ["pkg:oci/kube-ovn@v1.14.10?repository_url=index.docker.io/kubeovn/kube-ovn"]}'
```

This returns Rancher's `not_affected` with `status_notes` ending `scope=pkg:oci/kube-ovn?repository_url=index.docker.io/kubeovn/kube-ovn`, beside Ubuntu's own statements. Without `scopes`, only Ubuntu's come back.

- **On `/v1/statements`**, name scopes in `scopes`. With an SBOM, its `metadata.component` is added automatically.
- **On `/v1/analyze`**, the SBOM's `metadata.component` is the scope.
- **Scopes are normalised**: `repository_url` is kept. The tag, digest, version and other qualifiers are dropped.
- Without a scope, you get only package-level statements. Every other feed is unaffected.

## Debian source packages

Debian states its verdicts per **source** package (`zlib`). Scanners list **binary** packages (`zlib1g`), and Trivy applies a statement only to the exact binary PURL. reel-vex bridges the two on the SBOM paths (`sbom` on either endpoint).

```bash
jq '{sbom: .}' deb-sbom.json | curl -s https://vex.getreel.dev/v1/statements \
  -H 'Content-Type: application/json' -d @-
```

For an SBOM holding `pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.11&epoch=1` with Trivy's source properties (`SrcName` `zlib`, `SrcVersion` `1.2.13.dfsg`, `SrcRelease` `1`, `SrcEpoch` `1`) and CVE-2022-37434, the answer is Debian's `fixed`, named by the `zlib1g` PURL, with `match_reason=via_source_package`. On `/v1/analyze` the same SBOM gets `state: resolved`.

<details><summary>The <code>deb-sbom.json</code> used here</summary>

```json
{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
 "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
 "components": [{"bom-ref": "zlib1g", "type": "library", "name": "zlib1g",
   "purl": "pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.11&epoch=1",
   "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "zlib"},
                  {"name": "aquasecurity:trivy:SrcVersion", "value": "1.2.13.dfsg"},
                  {"name": "aquasecurity:trivy:SrcRelease", "value": "1"},
                  {"name": "aquasecurity:trivy:SrcEpoch", "value": "1"}]}],
 "vulnerabilities": [{"id": "CVE-2022-37434", "affects": [{"ref": "zlib1g"}]}]}
```
</details>

- **Which components**: a `pkg:deb/debian/…` component whose `aquasecurity:trivy:SrcName` property differs from its own name. It is also looked up as `pkg:deb/debian/<SrcName>` with its own `distro`.
- **Which version**: the source version Trivy records, `[SrcEpoch:]SrcVersion[-SrcRelease]`. Debian's fixed-in version is compared with that.
- **The answer names the binary**: as sent for a fixed-in row, in base form otherwise. Two binaries of one source package both appear.
- A package also reached directly keeps `match_reason=direct`.
- Exact-list rows (Ubuntu OpenVEX, Rancher) are never matched through a source package.
- Ubuntu gets no source lookup: its feeds already name binaries.

**A plain `products` query has no source name to read.** Name the source package to get Debian's verdicts: `pkg:deb/debian/zlib@…?distro=debian-12`. A binary PURL like `pkg:deb/debian/zlib1g@…` matches no Debian row there.

## PURL identity rules

These decide whether your PURL reaches a statement:

| Qualifier | Effect |
|---|---|
| `distro` | **Part of the identity.** `debian-12` and `debian-11` are different packages, and a `deb` PURL without `distro` matches no Debian or Ubuntu row. |
| `repository_id` | Not part of the identity. Red Hat's mapping turns it into a CPE (`via_alias`). Needed to reach Red Hat's EUS, AUS and E4S stream verdicts. |
| `arch` | Ignored, unless you set [`strict_arch`](#strict_arch). |
| `epoch` | Not part of the identity. Used only when [comparing versions](#versioned-queries). |
| anything else, and `#subpath` | Ignored. |

reel-vex also tries your PURL without `distro` (Red Hat CSAF publishes bare PURLs while scanners add `distro=redhat-9.x`), and at the major release where a feed stores that: `debian-12.11` → `debian-12`, `oracle-8.10` → `oracle-8`, `alma-9.1` → `almalinux-9`, `amazon-2023.7…` → `amazon-2023`, apk `3.21.3` → `alpine-3.21`. These only add matches.

## GET /v1/stats

```bash
curl -s https://vex.getreel.dev/v1/stats
```
```json
{"vendors":9,"cves":89598,"statements":227290205,"aliases":23267,"last_updated":"2026-10-15T15:36:51Z","version":"v0.13.1"}
```

`last_updated` is the latest feed sync. `version` is absent on a build without one. The counts are cached and refreshed after each ingest. Browsers may cache the answer for a minute, and show it stale for up to a day while refreshing.

**Right after a server start, the counts may not be ready yet.** The answer is then `503` with `Retry-After: 60` and `{"error": "stats warming up; retry shortly"}`. Wait and ask again. `Retry-After` is readable from a browser.

## GET /v1/ingest and POST /v1/ingest

`GET /v1/ingest` reports the ingest state:

```json
{"running": true, "last_run": "2026-10-15T15:52:40Z", "next_run": "2026-10-15T23:40:40Z"}
```

`last_error` appears when the last run failed.

`POST /v1/ingest` starts an ingest on a self-hosted server. When the server has `-admin-token`, send `Authorization: Bearer <token>` (otherwise `401`). **Without `-admin-token`, anyone can start one.** The answer is `202 {"status": "started"}`, or `409 ingest already running`.

## GET /healthz

`200 ok` when the database answers a ping within 2 seconds, otherwise `503 database unreachable`. A liveness probe on it will therefore restart the server during a database outage.

## CORS

Every endpoint sends `Access-Control-Allow-Origin: *` and answers `OPTIONS` preflights with `204`. Browsers can read `X-Reel-Truncated`, `X-Reel-Next-Offset`, `X-Reel-Converted`, `X-Reel-Grouped`, `X-Reel-Arch` and `Retry-After`.
