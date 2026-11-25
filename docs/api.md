# reel-vex API reference

reel-vex answers one question: **for these packages, what did the vendor say about these CVEs?** Vendors publish those answers as VEX (Vulnerability Exploitability eXchange): a verdict per CVE and product, such as `not_affected` or `fixed`. reel-vex collects them from nine vendors and serves them. The public instance, `https://vex.getreel.dev`, is free and needs no authentication.

Packages are named by PURL (Package URL, e.g. `pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12`) or by CPE (Common Platform Enumeration, e.g. `cpe:/o:redhat:enterprise_linux:8`).

| Method | Path | Use it to |
|---|---|---|
| `POST` | [`/v1/statements`](#post-v1statements) | Get vendor statements as OpenVEX, for CVE and package lists or a CycloneDX SBOM. Pair with `trivy image --vex`. |
| `POST` | [`/v1/analyze`](#post-v1analyze) | Get your SBOM back annotated, optionally merged with your own VEX. Pair with `trivy sbom --vex`. |
| `GET` | [`/v1/stats`](#get-v1stats) | Coverage counts. |
| `GET` | [`/v1/ingest`](#get-v1ingest-and-post-v1ingest) | Ingest status. `POST` starts one (admin). |
| `GET` | [`/healthz`](#get-healthz) | Health check, including the database. |

How matching works: [Versioned queries](#versioned-queries) · [Product-scoped statements](#product-scoped-statements) · [Debian source packages](#debian-source-packages) · [PURL identity rules](#purl-identity-rules)

## Quick recipes

Recipes were run against the live hub with Trivy 0.74.0.

### Hide vendor-cleared findings in `trivy image`

Scan for an SBOM, ask reel-vex, then scan again with the answer as VEX:

```bash
IMAGE=registry.access.redhat.com/ubi9-minimal
trivy image --format cyclonedx --scanners vuln "$IMAGE" > sbom.json
code=$(jq '{sbom: .}' sbom.json | curl -s -o vex.json -w '%{http_code}' \
  https://vex.getreel.dev/v1/statements -H 'Content-Type: application/json' -d @-)
if [ "$code" = 200 ]; then trivy image --vex vex.json "$IMAGE"; else trivy image "$IMAGE"; fi
```

Trivy hides the findings a vendor marked `not_affected` or `fixed` (10 of 199 on this image on 2026-10-20). Check the status: when no vendor said anything the answer is `204` with an empty body, and Trivy stops on it with `unable to decode VEX`.

### Annotate an SBOM for `trivy sbom`

```bash
jq '{sbom: .}' sbom.json | curl -s https://vex.getreel.dev/v1/analyze \
  -H 'Content-Type: application/json' -d @- > annotated.json
trivy sbom --vex annotated.json sbom.json
```

This can hide more findings than `/v1/statements`, because disagreeing vendor rows resolve to the most favourable verdict ([Annotation](#annotation)).

### Add your own VEX

Send your own OpenVEX with the SBOM. Your statement replaces the vendor's for the same CVE and package:

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

`via_alias` is a verdict for all of RHEL 8, reached through the `repository_id`. The `direct` rows are about `openssl` itself, one per product stream. Where streams disagree and a package gets both `affected` and `not_affected`, Trivy 0.74.0 keeps the finding.

## Response format

`/v1/statements`, and `/v1/analyze` when it gets only `user_vex`, return an [OpenVEX 0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) document, the only format. This one answers `{"cves": ["CVE-2022-37434"], "products": ["pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12"]}`:

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

- **No match is `204 No Content`** with an empty body.
- **One statement can name many products.** Rows equal in every statement field are sent once with all their products, so iterate the whole `products[]`.
- **Every status the vendor stated is returned**: `not_affected`, `fixed`, `affected` or `under_investigation`. Trivy ignores the last two.

### Fields

| Field | What it holds |
|---|---|
| `@id` | A hash of the content: same query, same data, same `@id`. |
| `timestamp` | Document: when this response was made. Statement: when the vendor last updated the verdict. |
| `author`, `role`, `version` | Always `reel-vex aggregator <vex@getreel.dev>`, `aggregator`, `1`. Not signed. |
| `products[]` | A PURL is in `@id` and `identifiers.purl`, a CPE in `identifiers.cpe23` only. See [Which identifiers come back](#which-identifiers-come-back). |
| `justification` | Why it is `not_affected`, when the vendor said (one of the five OpenVEX values). |
| `impact_statement` | On a `not_affected` without justification: `Not affected per vendor statement; no justification supplied.` |
| `action_statement` | On every `affected`: `Follow vendor advisory for remediation.` |
| `supplier` | `redhat`, `suse`, `rancher`, `ubuntu`, `debian`, `alpine`, `amazon`, `almalinux` or `oracle`. Your own VEX keeps the `supplier` you sent. |

### `status_notes`

`; `-separated `key=value` pairs:

| Key | When |
|---|---|
| `source_format` | Every vendor statement: `csaf`, `oval`, `openvex`, `secdb` or `updateinfo`. |
| `match_reason` | When the request named products, or sent an SBOM or user VEX. See [Match reasons](#match-reasons). |
| `scope` | [Product-scoped](#product-scoped-statements) statements: the image or module the verdict is about. |
| `converted_from`, `original_state`, `original_justification`, `fidelity` | Your own VEX, when converted from CycloneDX. |

### Match reasons

| `match_reason` | The statement matched because |
|---|---|
| `from_user_vex` | it is your own statement. It overrides vendor rows. |
| `direct` | its package is the one you named (version and filter qualifiers aside). |
| `via_alias` | your PURL's `repository_id` maps to a Red Hat CPE the statement is about. |
| `via_cpe_prefix` | your CPE 2.2 URI matches its first five parts (`part:vendor:product:version:update`), per Red Hat's [SECDATA-1220](https://redhat.atlassian.net/browse/SECDATA-1220). |
| `via_source_package` | SBOM input only: it is about the Debian source package your component was built from. |

When several rules reach one statement, the one highest in this table is reported.

## POST /v1/statements

Send CVEs, packages, a CycloneDX SBOM, or any mix, and get the matching vendor statements as [OpenVEX](#response-format).

### Request

| Field | Type | Meaning |
|---|---|---|
| `cves` | string[] | CVE ids. |
| `products` | string[] | PURLs or CPEs. |
| `sbom` | object | A CycloneDX 1.4+ SBOM, inline ([SBOM input](#sbom-input)). |
| `vendors`, `source_formats`, `statuses`, `justifications` | string[] | Keep only these values. |
| `scopes` | string[] | Images or modules you scan. Opts in [product-scoped statements](#product-scoped-statements). |
| `strict_arch` | bool | Drop other architectures' statements ([`strict_arch`](#strict_arch)). Default `false`. |
| `since` | RFC 3339 | Keep statements the vendor updated at or after this time. |
| `limit`, `offset` | int | [Paging](#paging-and-truncation). `limit` can only lower the server's cap. |

- **You need at least one of `cves`, `products` or `sbom`**, or the answer is `400` with `one of cves, products, or sbom (with components or vulnerabilities) is required`.
- **Filters combine with AND, values in one filter with OR.** An empty field filters nothing.
- **Without `cves`, you get every statement for the packages** (broad mode), the usual way to fetch VEX for an image. Trivy matches CVEs itself, so one cached document serves every scan. Check [`X-Reel-Truncated`](#paging-and-truncation).
- **With `cves` and no `products`**, statements come under the vendors' own identifiers, often CPEs, which Trivy's `--vex` ignores (it matches on PURL only).

### SBOM input

CVEs come from `vulnerabilities[].id`, packages from the top-level `components[].purl` and `components[].cpe` (and [Debian source packages](#debian-source-packages)), and the scope from `metadata.component`. They add to any `cves`, `products` and `scopes` you send.

### Which identifiers come back

The answer names packages your way, because Trivy matches by PURL. **Base form** means no version and no qualifier except `distro`.

| Row kind | Named in `products[]` as |
|---|---|
| Most rows | your identifier in base form. |
| [Fixed-in rows](#versioned-queries), when you sent a version | your identifier exactly as sent. |
| [Exact-list rows](#versioned-queries) | the vendor's identifier, once per matching version, written as Trivy writes it. |
| Any row, when you named no products | the vendor's stored identifier, possibly a CPE. |

A CPE you send is passed through as written.

### `strict_arch`

Matching ignores architecture by default, so an `amd64` scan also gets `arm64` and `s390x` statements. With `"strict_arch": true`, a row is kept only if its product has no `arch`, an architecture-independent one (`noarch`, `src`, `source`, `all`), or one your products name.

```bash
curl -s https://vex.getreel.dev/v1/statements -H 'Content-Type: application/json' \
  -d '{"cves": ["CVE-2022-37434"], "strict_arch": true,
       "products": ["pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04&epoch=1"]}'
```

Canonical's statement then names only the `amd64` build, not seven, and `X-Reel-Arch: amd64` is set. The architectures are the union over your products. If none has an `arch`, nothing is filtered.

### Paging and truncation

The server returns at most `-statements-max` rows (default **50,000**, `0` = no cap), or your `limit` if lower. A cut result stays `200` and says so:

```
X-Reel-Truncated: true
X-Reel-Next-Offset: 100
```

Repeat with `"offset": 100` for the next page. **A truncated document is incomplete**: a statement it leaves out is a finding Trivy will not hide.

<details><summary>Paging details</summary>

- Rows come in a fixed order (package, CVE, product, feed format), so pages never overlap while data is unchanged.
- `limit`, `offset` and the counts cover only rows that survive version selection.
- `strict_arch` is applied again after the page is cut, so a page can be shorter than `limit`, or a `204` with no body, and still truncated. Keep paging while `X-Reel-Truncated` is set.
</details>

### Response headers

| Header | Meaning |
|---|---|
| `X-Reel-Mode` | `cve` or `broad`. |
| `X-Reel-Statements` | Rows in this page, after version selection and `strict_arch`. |
| `X-Reel-Grouped` | Statements in the document after grouping. |
| `X-Reel-CVE` | The CVE, when exactly one was asked about. |
| `X-Reel-Arch` | Architectures `strict_arch` applied, when it applied any. |
| `X-Reel-Truncated`, `X-Reel-Next-Offset` | The result was cut. |

Which a browser can read is under [CORS](#cors). Send `Accept-Encoding: gzip` for a compressed answer. A `204` is never compressed.

### Errors

Errors carry `{"error": "<message>"}`.

| Status | When |
|---|---|
| `400` | Invalid JSON or SBOM; no CVEs or products; over 10,000 items in `cves` or `products`, SBOM included (`-max-statements-items`); an SBOM over 50,000 components or 10,000 vulnerabilities. |
| `413` | Body over `-sbom-max-mb` (default 10 MB). Without `Content-Length`, an oversized body gets `400 invalid JSON`. |
| `500` | `query failed`. |
| `503` | A query past `-query-timeout` (default 20 s). Narrow the CVEs or products, or page with a smaller `limit`. |

## POST /v1/analyze

Send a CycloneDX SBOM, your own VEX, or both ([recipes](#annotate-an-sbom-for-trivy-sbom)).

### Request

| Field | Type | Meaning |
|---|---|---|
| `sbom` | object | A CycloneDX 1.4+ SBOM, inline. |
| `user_vex` | object[] | Up to 10 VEX documents: OpenVEX 0.2.0, or CycloneDX with VEX. |
| `strict_arch` | bool | Narrow vendor rows to the SBOM components' architectures, as on [`/v1/statements`](#strict_arch). |
| `reject_cyclonedx_lossy` | bool | Drop CycloneDX VEX statements with no exact OpenVEX equivalent, instead of mapping them to the nearest. Default `false`. |

You need `sbom` or `user_vex`, or the answer is `400` with `at least one of sbom or user_vex required`. The body is inline JSON, not multipart.

### What comes back

| You send | You get |
|---|---|
| `sbom` with `vulnerabilities[]` | The SBOM, with an `analysis` on each vulnerability a vendor or you spoke about. |
| `sbom` without `vulnerabilities[]` | The SBOM, with vulnerabilities built from every vendor statement about its components ([broad mode](#broad-mode-sboms-without-vulnerabilities)). |
| `user_vex` only | OpenVEX: your statements, plus vendor statements for the same CVEs and packages that yours do not override. `204` if none of yours were valid. |
| both | The annotated SBOM, your statements taking precedence. |

With an SBOM the answer is always `200`, even when nothing matched. An `affects[].ref` that is a component's PURL becomes the BOM-Link `trivy sbom --vex` needs, `urn:cdx:<serialNumber>/<version>#<bom-ref>`. Without a `serialNumber` or a matching `bom-ref` it is left alone, and Trivy logs `Unable to parse BOM-Link`.

### Annotation

Each `analysis` has a `state`, a `justification` when there is one, and a `detail` naming every statement that took part, such as `redhat: affected; redhat: not_affected (vulnerable_code_not_present)`.

| OpenVEX status | CycloneDX `state` | Rank |
|---|---|---|
| `not_affected` | `not_affected` | 1 (wins) |
| `fixed` | `resolved` | 2 |
| `under_investigation` | `in_triage` | 3 |
| `affected` | `exploitable` | 4 |

- **When one component's rows disagree, the best rank wins**: one Red Hat stream's `affected` and another's `not_affected` annotate as `not_affected`.
- **Justifications map** to `code_not_present` (from `component_not_present`, `vulnerable_code_not_present`), `code_not_reachable` (`vulnerable_code_not_in_execute_path`) and `protected_by_mitigating_control` (`inline_mitigations_already_exist`). `vulnerable_code_cannot_be_controlled_by_adversary` is left out.
- **Verdicts are judged per component**, at its own version. A vulnerability is annotated only if **every** component in its `affects[]` has a verdict and all agree on the state. The justification is kept only if they agree on it too.
- A vulnerability naming no SBOM component gets the verdict of all rows for its CVE.

### Broad mode: SBOMs without vulnerabilities

If `vulnerabilities[]` is missing or empty, reel-vex writes one annotated vulnerability per CVE any vendor stated about the SBOM's components. An SBOM that has vulnerabilities is never extended. The lookup is capped at `-statements-max` rows: past it the answer is still `200`, with `X-Reel-Truncated: true` and some CVEs missing. There is no offset here, so send fewer components.

### User-VEX merge semantics

- **Your statement overrides the vendor's** for the same CVE and package. Packages are compared in base form, CPEs as written.
- **One statement of yours about a CVE decides that CVE for the whole SBOM.** Only your statements annotate it, on every component, so a vendor `not_affected` cannot outrank your `affected`.
- **Two of yours on one CVE and package**: the newer `timestamp` wins, then the later in the request. A missing `timestamp` falls back to the document's, then the request time.
- **Vendor rows are narrowed by the SBOM's versions and `strict_arch`. Yours never are.**
- **CycloneDX VEX is converted**, as are CycloneDX words in OpenVEX (`requires_environment` becomes `vulnerable_code_cannot_be_controlled_by_adversary`, flagged `fidelity=lossy`).
- **An invalid statement is skipped, not refused**: an unknown status or justification, `not_affected` without justification, a justification on another status, a product with no `@id`, `purl`, `cpe22` or `cpe23`, or a CycloneDX `false_positive` without justification.
- **`X-Reel-Converted`**, sent when anything was converted or skipped, counts it: `converted=1; lossy=0; contested=0; skipped=0`.
- **Your VEX is never stored or logged.**

### Limits and errors

| Rule | Limit | Status |
|---|---|---|
| Request body | 10 MB (`-sbom-max-mb`) | `413` |
| `user_vex` documents | 10 | `400` |
| Statements across `user_vex` | 25,000 (`-max-user-vex-statements`) | `400` |
| Products in one statement | 100 | `400` |
| SBOM components | 50,000 (`-max-sbom-components`) | `400` |
| SBOM vulnerabilities | 10,000 (`-max-sbom-vulns`) | `400` |
| Distinct CVEs to look up | 10,000 (`-analyze-max-cves`) | `400` |
| `@context` other than `https://openvex.dev/ns/v0.2.0`, or an unreadable document | | `422` |
| Lookup past `-query-timeout` (20 s) | | `503` |

Response headers: `X-Reel-Mode` (`broad` when vulnerabilities were built), `X-Reel-Statements` (rows after the merge), `X-Reel-Arch`, `X-Reel-Truncated` (broad mode only, with no next offset), `X-Reel-Converted`, and `X-Reel-Grouped` with OpenVEX only. There is no `X-Reel-CVE` or `X-Reel-Next-Offset`. See [`/v1/statements`](#response-headers) for what each means.

## Versioned queries

A version in a PURL limits the answer to verdicts that hold for that version. Without one you get every verdict. What "holds" means depends on the feed:

| Feeds | The vendor states | A versioned query gets |
|---|---|---|
| Debian, Ubuntu OVAL, AlmaLinux, Oracle, Alpine, Amazon (**fixed-in**) | `fixed` in version X | `fixed` if your version is X or later |
| Ubuntu OpenVEX, Rancher (**exact-list**) | a verdict for listed builds | the verdict for your exact build, or nothing |
| Red Hat, SUSE (**version-blind**) | a verdict per product stream | every verdict |

### Example

CVE-2022-37434 in zlib. Debian fixed it in `1:1.2.11.dfsg-4.1` for bookworm. Canonical lists Ubuntu 22.04's `zlib1g` at `1:1.2.11.dfsg-2ubuntu9.2` as `fixed`. Each request was `{"cves": ["CVE-2022-37434"], "products": ["<the PURL>"]}`.

| `products` | Answer |
|---|---|
| `pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12` | `fixed`: later than the fix |
| `pkg:deb/debian/zlib@1:1.2.11.dfsg-2?distro=debian-12` | `204`: earlier than the fix |
| `pkg:deb/debian/zlib@1.2.13.dfsg-1?distro=debian-12` | `204`: no epoch is epoch 0, earlier than `1:` |
| `pkg:deb/debian/zlib?distro=debian-12` | `fixed`, named without a version |
| `pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04&epoch=1` | `fixed` twice: Canonical's OpenVEX lists this build, and Ubuntu OVAL's fix is reached |
| `pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.5?arch=amd64&distro=ubuntu-22.04&epoch=1` | `fixed` from Ubuntu OVAL only: Canonical never listed this build |

### Rules

- **Fixed-in versions are compared as dpkg, rpm or apk would.**
- **`epoch=1` and a `1:` prefix are the same**; neither means epoch 0. Versions are percent-decoded first (`%2B` is `+`, and `+` is never a space).
- **Exact-list feeds are strict on purpose.** A new Ubuntu build gets nothing from Canonical's OpenVEX until Canonical lists it, which can leave open a finding a `not_affected` would have hidden.
- **Only `fixed` rows carry a fixed-in version.** Other verdicts from fixed-in feeds hold for every version, such as Debian's open CVEs (`affected`) and Alpine's `"0"` (`not_affected`).
- **Red Hat and SUSE ignore the version**, because reel-vex does not record their product streams.

<details><summary>Edge cases</summary>

- An exact-list row with no version at all (Rancher's deb, rpm and apk subcomponents) matches any version and is named by the vendor's versionless PURL.
- Where a feed states several fixed-in versions for one package and CVE, one is kept, possibly another stream's. A version below it gets no `fixed`.
</details>

## Product-scoped statements

Rancher states verdicts about a package **inside one image or Go module** (the scope). reel-vex returns such a statement only when you name its scope, so a verdict about one image never hides the same package in another.

```bash
curl -s https://vex.getreel.dev/v1/statements -H 'Content-Type: application/json' \
  -d '{"cves": ["CVE-2026-24061"],
       "products": ["pkg:deb/ubuntu/inetutils-ping?distro=ubuntu-22.04"],
       "scopes": ["pkg:oci/kube-ovn@v1.14.10?repository_url=index.docker.io/kubeovn/kube-ovn"]}'
```

This returns Rancher's `not_affected`, with `status_notes` ending `scope=pkg:oci/kube-ovn?repository_url=index.docker.io/kubeovn/kube-ovn`, beside Ubuntu's statements. Without `scopes`, only Ubuntu's come back.

- Name scopes in `scopes`. On either endpoint, an SBOM's `metadata.component` counts as one.
- **Scopes keep `repository_url`** and drop the tag, digest, version and other qualifiers.

## Debian source packages

Debian states verdicts per **source** package (`zlib`). Scanners list **binary** packages (`zlib1g`), and Trivy needs the exact binary PURL. When you send an `sbom`, either endpoint bridges the two.

```bash
jq '{sbom: .}' deb-sbom.json | curl -s https://vex.getreel.dev/v1/statements \
  -H 'Content-Type: application/json' -d @-
```

The answer is Debian's `fixed`, named by the `zlib1g` PURL, with `match_reason=via_source_package`. `/v1/analyze` gives the same SBOM `state: resolved`.

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

- A `pkg:deb/debian/…` component whose `aquasecurity:trivy:SrcName` differs from its name is also looked up as `pkg:deb/debian/<SrcName>` (same `distro`), at version `[SrcEpoch:]SrcVersion[-SrcRelease]`.
- **The answer names the binary**: as sent for a fixed-in row, in base form otherwise.
- Exact-list rows are never matched this way, and Ubuntu gets no source lookup (its feeds name binaries).

**A plain `products` query has no source name to read**, so name the source package (`pkg:deb/debian/zlib@…`). A binary PURL like `pkg:deb/debian/zlib1g@…` matches no Debian row there.

## PURL identity rules

| Qualifier | Effect |
|---|---|
| `distro` | **Part of the identity.** `debian-12` and `debian-11` are different packages, and a `deb` PURL without `distro` matches no Debian or Ubuntu row. |
| `repository_id` | Not part of the identity. Red Hat's mapping turns it into a CPE (`via_alias`). Needed to reach Red Hat's EUS, AUS and E4S stream verdicts. |
| `arch` | Ignored, unless you set [`strict_arch`](#strict_arch). |
| `epoch` | Not part of the identity. Used only when [comparing versions](#versioned-queries). |
| anything else, and `#subpath` | Ignored. |

A PURL is also tried without its `distro`, and at the major release where a feed stores that: `debian-12.11` → `debian-12`, `oracle-8.10` → `oracle-8`, `alma-9.1` → `almalinux-9`, `amazon-2023.7…` → `amazon-2023`, apk `3.21.3` → `alpine-3.21`. These only add matches.

## GET /v1/stats

```bash
curl -s https://vex.getreel.dev/v1/stats
```
```json
{"vendors":9,"cves":89598,"statements":227290205,"aliases":23267,"last_updated":"2026-10-15T15:36:51Z","version":"v0.13.1"}
```

`last_updated` is the latest feed sync. `version` is absent on a build without one. Counts refresh after each ingest. Browsers may cache it for a minute, and use a stale copy for up to a day while refreshing.

**Right after a server start**, the answer can be `503` with `Retry-After: 60` and `{"error": "stats warming up; retry shortly"}`. `Retry-After` is browser-readable.

## GET /v1/ingest and POST /v1/ingest

`GET /v1/ingest` reports the ingest state, with `last_error` when the last run failed:

```json
{"running": true, "last_run": "2026-10-15T15:52:40Z", "next_run": "2026-10-15T23:40:40Z"}
```

`POST /v1/ingest` starts an ingest. When the server has `-admin-token`, send `Authorization: Bearer <token>` (otherwise `401`). **Without `-admin-token`, anyone can start one.** The answer is `202 {"status": "started"}`, or `409 ingest already running`.

## GET /healthz

`200 ok` when the database answers a ping within 2 seconds, otherwise `503 database unreachable`. A liveness probe on it will restart the server during a database outage.

## CORS

Every endpoint sends `Access-Control-Allow-Origin: *` and answers `OPTIONS` preflights with `204`. Browsers can read `X-Reel-Truncated`, `X-Reel-Next-Offset`, `X-Reel-Converted`, `X-Reel-Grouped`, `X-Reel-Arch` and `Retry-After`.
