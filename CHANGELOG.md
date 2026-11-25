# Changelog

Notable changes to reel-vex. Before 1.0 a minor version can break things: such changes are marked **Breaking** and listed under **Upgrade notes**.

## [Unreleased]

### Fixed
- **Ubuntu OpenVEX refuses a tarball over 1 GiB** rather than buffering it whole; Canonical's is about 70 MB.

## [0.13.3] — Ubuntu OpenVEX emits each statement once

*Released 2026-11-25*

### Fixed
- **Ubuntu OpenVEX emits each statement once when a publish is read whole.** It emitted the changed documents and then the whole feed, which doubled the sweep's seen rows past its temporary-file limit; the sweep failed and the next ingest read the feed again.

## [0.13.2] — paging headers on a 204, timeouts are 503, security fixes

*Released 2026-11-25*

### Fixed
- **`/v1/statements` keeps `X-Reel-Truncated` and `X-Reel-Next-Offset` on a `204`** when `strict_arch` empties a truncated page, so a client keeps paging.
- **`/v1/statements` answers a query past `-query-timeout` with `503`**, as `/v1/analyze` and the flag's help do. It was `500`.

### Security
- **`klauspost/compress` 1.20.5** fixes [GO-2026-6865](https://pkg.go.dev/vuln/GO-2026-6865), a panic on a crafted zstd frame, reached through the Red Hat CSAF archive.
- **Built with Go 1.27.4 or later**, which fixes [GO-2026-6859](https://pkg.go.dev/vuln/GO-2026-6859), an HTTP server crash, and the Go 1.27.3 `crypto/x509` fix. 0.13.1 was built with Go 1.27.2.

### Changed
- Dependencies: `pgx` 5.13.0, `gocsaf/csaf` 3.7.1, and their indirect modules.

## [0.13.1] — Ubuntu OpenVEX reads only what changed

*Released 2026-10-15*

**Upgrade notes:** Rolls in place. It adds an empty `adapter_documents` table; after a rollback to 0.13.0, delete its rows before upgrading again.

### Changed
- **Ubuntu OpenVEX re-reads only changed documents**: minutes per publish, not hours, same answers.
- The first run after upgrading, and any run with `-sweep-max-fraction 0`, reads the whole tarball.
- **A publish changing more than a fifth of the documents, and more than 1,000,** is read whole and swept under `-sweep-max-fraction`. See [Removal](docs/architecture.md#removal).
- **CVEs that leave the tarball are withdrawn** under the same guard, logging `withdraw`.
- **To force a full read**, delete the adapter's `adapter_documents` rows.
- **A publish whose removal did not finish is fetched again** next run (or by a `-sweep-force` run).

## [0.13.0] — removal, version-aware answers

*Released 2026-10-12*

**Upgrade notes:**
- **Start from an empty database**: removal never deletes rows from earlier versions. Let the first ingest fill it.
- **Edit `config.yaml`** (the release's copy has all three):
  - Remove any `redhat-oval` entry, or the server does not boot (`unknown adapter type`).
  - Point `rancher-vex` at `https://github.com/rancher/vexhub/archive/refs/heads/main.tar.gz`; `index.json` fails every sync.
  - Each `oracle-oval` URL must name a release file (`com.oracle.elsa-ol<N>.xml.bz2`), or the server does not boot (`cannot read the release from url`).
- **`/healthz` answers `503 database unreachable` when the database misses a ping**, so a liveness probe restarts the app during a database outage.
- **Removal is on by default** (`-sweep-max-fraction 0.2`; `0` turns it off). A full Ubuntu OpenVEX sweep needs up to ~116 GB of temporary disk on the database host.
- **One ingest per database.** A second `ingest` exits non-zero (`another ingest is running`); a `serve` scheduler logs it and skips.
- **Breaking:** a versioned query can now get nothing where it used to get `fixed`.
- **Breaking:** `/v1/analyze` leaves a vulnerability unannotated when its `affects[]` components disagree.

### Changed
- **Breaking: a versioned query gets only verdicts that hold for that version.** See [Versioned queries](docs/api.md#versioned-queries).
  - Debian, Ubuntu OVAL, AlmaLinux, Oracle, Alpine, Amazon: `fixed` only at or above the fixed-in version, under the PURL you sent.
  - Ubuntu OpenVEX, Rancher: the verdict for that exact build, nothing for an unlisted one. Red Hat and SUSE CSAF: unchanged.
- **Ubuntu OpenVEX and Rancher answer under the vendor's versioned identifiers**, as Trivy writes them; a versionless query gets every listed build.
- **Breaking: `/v1/analyze` attributes verdicts per component**; disagreeing components leave no analysis. See [POST /v1/analyze](docs/api.md#post-v1analyze).
- **Verdicts that used to overwrite each other are all returned**: Red Hat CSAF per product stream, Ubuntu ESM/FIPS tracks, Rancher keys with conflicting justifications.
- **A changed verdict is a new row**; while removal is off or refused, old and new are both served.
- **`offset` paging never repeats or skips a row**, even among rows sharing an identifier.
- **`limit`, `X-Reel-Statements` and `X-Reel-Truncated` count only the rows returned** after version matching.
- **The `adapter done` log line** carries `complete`, `refreshed` and `live`.

### Added
- **Removal** of rows a vendor stops publishing, guarded by `-sweep-max-fraction` (`1` lifts the fraction guards); `-sweep-force <adapter-id>[,…]` overrides. See [Removal](docs/architecture.md#removal).
- **Debian binaries are answered from their source package** (`libc6` → `glibc`) on SBOM input, with `match_reason=via_source_package`; a plain `products` query must name the source package. See [Debian source packages](docs/api.md#debian-source-packages).
- **Alpine 3.24** feeds (`alpine-secdb-v3.24-main`, `alpine-secdb-v3.24-community`).

### Removed
- **Red Hat OVAL.** RHEL 9.6 EUS queries lose `fixed` for CVEs fixed before the EUS branch point.

### Fixed
- **Verdicts:** SUSE fixed packages are `fixed` (none were); Alpine `"0"` is `not_affected`; Debian `0:0` is `affected`; each Oracle adapter keeps only its release.
- **Red Hat cold starts** date archived rows by their own document (so `since` is right) and no longer store an archived copy beside the current one.
- **Identifier matching:** `trusty/esm` reaches Ubuntu 14.04; `debian-12.11` and `oracle-8.10` reach their major release; Amazon `product_id`s are valid PURLs.
- **Also:** npm-scoped PURLs keep their name; echoes keep the caller's encoding; `match_reason` names the strongest rule; Rancher error text is no longer stored as a product.

## [0.12.2]

*Released 2026-08-24*

### Fixed
- **The `/v1/stats` time limit holds** even if its process exits.
- **Browsers can read `Retry-After`.**

## [0.12.1]

*Released 2026-08-24*

**Upgrade notes:** With the bundled `docker-compose.yml`, recreate the Postgres container to apply `shm_size: 1gb`.

### Changed
- **`/v1/stats` answers `503` with `Retry-After: 60` while computing**, and is ready within minutes of a restart.
- **The stats computation is capped at 20 minutes.**

## [0.12.0] — grouped statements, `strict_arch`

*Released 2026-08-24*

**Upgrade notes:** A count of `statements[]` changes. No migration; to roll back, redeploy the previous image.

### Changed
- **Breaking for counters:** rows agreeing on CVE, status, justification, supplier, timestamp and `status_notes` are one statement listing all their products. `X-Reel-Statements` still counts rows.

### Added
- **`strict_arch`** (default `false`): only rows with no `arch`, `noarch`/`src`/`source`/`all`, or an `arch` you named.
- **`X-Reel-Grouped`** and **`X-Reel-Arch`** headers, both readable by browsers.

### Fixed
- **`products` queries no longer return duplicate statements.**

## [0.11.1]

*Released 2026-07-13*

### Added
- **`X-Reel-CVE` header** on `/v1/statements` when exactly one CVE was queried.

## [0.11.0]

*Released 2026-07-13*

### Added
- **`X-Reel-Mode`** (`cve` or `broad`) and **`X-Reel-Statements`** headers on `/v1/statements` and `/v1/analyze`, on `200` and `204`.

## [0.10.0] — four OS feeds

*Released 2026-06-09*

**Upgrade notes:** Add the new adapters to `config.yaml` (the release's copy has them); unlisted adapters do not run.

### Added
- **Alpine secdb** (adapter type `alpine-secdb`, vendor `alpine`, `source_format` `secdb`), per branch.
- **Amazon Linux** (adapter type `amazon-alas`, vendor `amazon`, `source_format` `updateinfo`), amzn2 and al2023 core.
- **AlmaLinux and Oracle Linux OVAL** (adapter types `almalinux-oval` and `oracle-oval`). AlmaLinux answers under both `pkg:rpm/almalinux/` and `pkg:rpm/alma/`.
- **Point-release distros match** for these feeds: `alpine-3.21.2` → `alpine-3.21`, `amazon-2023.7.x` → `amazon-2023`, `almalinux-9.1` → `almalinux-9`.

## [0.9.2]

*Released 2026-06-07*

**Upgrade notes:** The bundled `docker-compose.yml` refuses to start until `ADMIN_TOKEN` is set in `.env`. It gates `POST /v1/ingest`.

### Changed
- **`-analyze-max-cves` defaults to 10000** (was 500).
- **`docker-compose.yml`** runs `-ingest-interval 4h` and pins the image tag.

## [0.9.1]

*Released 2026-06-05*

### Changed
- **The broad-mode index is built after each ingest**, so an empty database loads fast. A 0.9.0 database keeps its index.

## [0.9.0] — Postgres

*Released 2026-06-05*

**Upgrade notes:** **Breaking:** reel-vex needs PostgreSQL. `-db` takes a `postgres://` URL. Nothing is imported from SQLite; the first ingest fills the new database.

### Added
- **`-no-scheduler`**: serve without the in-process ingest, beside a separate `ingest` worker.
- **`docker-compose.yml` and `.env.example`**: the app plus Postgres.

### Removed
- **The SQLite backend.**

## [0.8.5]

*Released 2026-06-05*

### Added
- **Limit flags**, defaults unchanged: `-query-timeout` (20s), `-max-sbom-components` (50000), `-max-sbom-vulns` (10000), `-max-statements-items` (10000), `-max-user-vex-statements` (25000).
- **The HTTP write timeout follows `-query-timeout`**: `max(30s, query-timeout + 10s)`.

## [0.8.4]

*Released 2026-06-02*

### Changed
- **A restart ingests only when data is at least one interval old** (and once after upgrading). `POST /v1/ingest` still forces a run.

## [0.8.3]

*Released 2026-06-02*

### Changed
- **`-analyze-max-cves`** sets the `/v1/analyze` CVE cap (default 500, was a fixed 800).

## [0.8.2]

*Released 2026-06-02*

### Changed
- **`/v1/analyze` CVE cap 1000 → 800; statement query timeout 15 s → 20 s.**

## [0.8.1]

*Released 2026-06-02*

### Changed
- **`/v1/analyze` answers `400` above 1000 distinct CVEs**; split or narrow the document.
- **Statement queries time out after 15 s** and answer `503`.

## [0.8.0] — CycloneDX VEX input

*Released 2026-06-02*

### Added
- **`user_vex` accepts CycloneDX VEX**, converted to OpenVEX, with `converted_from`, the original justification and `fidelity` in `status_notes`.
- **`reject_cyclonedx_lossy`** (default `false`) drops statements whose conversion is not exact.
- **`X-Reel-Converted` header** with converted, lossy, contested and skipped counts.

### Changed
- **A malformed user-VEX statement is skipped and counted**, not fatal. Numeric limits still answer `400`.
- **User-VEX statement cap 1000 → 25000.**
- **OpenVEX using CycloneDX words is converted**, not rejected (reverses 0.7.1).

## [0.7.1]

*Released 2026-06-02*

### Changed
- **`-sbom-max-mb` defaults to 10** (was 5).
- **OpenVEX using CycloneDX words** (`requires_environment`, `in_triage`, …) is rejected with one clear error.

### Fixed
- **Rancher statements carry the document's timestamp**, so `since` filters them correctly.
- **Rancher syncs no longer drop files** past GitHub's 300-file compare limit.

## [0.7.0]

*Released 2026-05-27*

### Added
- **`version` in `/v1/stats`**: the server build, or `dev`.

## [0.6.4]

*Released 2026-05-27*

**Upgrade notes:** In `config.yaml`, change the `rancher-vex` URL from `…/reports/rancher.openvex.json` to `…/refs/heads/main/index.json`.

### Changed
- **Rancher is read per file through `index.json`**, which returns more Rancher statements.

## [0.6.3]

*Released 2026-05-27*

### Changed
- **`updated`, and so `since`, tracks the last real change** to a verdict, not the last re-publish.

## [0.6.2]

*Released 2026-05-27*

### Added
- **Feed downloads retry** network errors, `429`, `500`, `502`, `503` and `504` up to 3 times.

## [0.6.1]

*Released 2026-05-27*

### Fixed
- **Browsers can read `X-Reel-Truncated` and `X-Reel-Next-Offset`.**

## [0.6.0] — SUSE Rancher VEX hub

*Released 2026-05-26*

**Upgrade notes:** A forward-only migration rewrites the `statements` table; to roll back, restore a backup taken before upgrading. Add the `rancher-vex` entry to `config.yaml`.

### Added
- **SUSE Rancher VEX hub** (vendor `rancher`): `not_affected` verdicts scoped to product images. Statements without a CVE id are skipped. See [Product-scoped statements](docs/api.md#product-scoped-statements).
- **`scopes` on `/v1/statements`.** A scoped verdict comes back only when you name its scope, or an SBOM's `metadata.component` does.
- **Scoped rows carry `scope=` in `status_notes`.** Answers without a scope are unchanged.

## [0.5.1] — broad mode

*Released 2026-05-26*

### Added
- **Broad mode on `/v1/statements`**: products without CVEs return all their statements. Only neither CVEs nor products is a `400`.
- **`-statements-max`** (default 50000, `0` unlimited). A capped answer is `200` with `X-Reel-Truncated: true` and `X-Reel-Next-Offset`; page with `limit` and `offset`.
- **gzip responses** for `Accept-Encoding: gzip` (not on `204` or `304`).
- **Red Hat CSAF cold starts read the weekly bulk archive**: minutes, not hours.

### Changed
- **`/v1/analyze` fills in an SBOM with no `vulnerabilities`** from a broad lookup, then annotates it.
- **Results come back in a fixed order.**
- **Empty-input error:** `one of cves, products, or sbom (with components or vulnerabilities) is required`.

## [0.5.0] — SBOM input

*Released 2026-05-03*

### Added
- **`sbom` on `/v1/statements`**: CVEs from `vulnerabilities[].id`, products from `components[].purl` and `.cpe`, merged with `cves` and `products`. `cves` becomes optional.
- **`-sbom-max-mb`** (default 5) caps the body on `/v1/analyze` and `/v1/statements`.

### Changed
- **`/v1/statements` body cap 1 MB → 5 MB.**
- **Empty-input error:** `one of cves or sbom (with vulnerabilities) is required`.

## [0.4.4]

*Released 2026-05-03*

### Changed
- **`/v1/analyze` writes `affects[].ref` as a BOM-Link**, so `trivy sbom --vex` applies it. Without `serialNumber`, `version` or `bom-ref`, the ref stays as sent.

## [0.4.3]

*Released 2026-05-03*

### Fixed
- **An RPM PURL with `?distro=`**, as Trivy and syft write it, also matches Red Hat rows stored without it.

## [0.4.2] — Canonical OpenVEX

*Released 2026-05-02*

**Upgrade notes:** Add the `ubuntu-vex` entry to `config.yaml`.

### Added
- **Canonical OpenVEX** (`source_format` `openvex`), with pre-USN triage (`not_affected`, `under_investigation`). Ubuntu OVAL stays alongside.

### Changed
- **`/v1/stats` is served from a cache**, refreshed after each ingest and warmed at startup.

## [0.4.1] — `user_vex` rename

*Released 2026-04-27*

**Upgrade notes:** **Breaking rename**, same behaviour. A request still sending `customer_vex` gets `400` (`at least one of sbom or user_vex required`).

| Old | New |
|---|---|
| `customer_vex` on `POST /v1/analyze` | `user_vex` |
| `match_reason=from_customer_vex` | `match_reason=from_user_vex` |

## [0.4.0] — `POST /v1/statements`

*Released 2026-04-27*

**Upgrade notes:** **Breaking.** Three routes now answer `404`:

| Old | New |
|---|---|
| `GET /v1/cve/{id}` | `POST /v1/statements` with `{"cves": ["<id>"]}` |
| `GET /v1/cve/{id}/summary` | none |
| `POST /v1/resolve` | `POST /v1/statements` with the same body |

### Added
- **`POST /v1/statements`** with filters `vendors`, `statuses`, `justifications`, `since` and `source_formats`: AND across filters, OR within one. See [POST /v1/statements](docs/api.md#post-v1statements).

## [0.3.0] — OpenVEX everywhere, user-VEX merge

*Released 2026-04-27*

**Upgrade notes:** **Breaking:**
1. **`POST /v1/sbom` is removed** (`404`). Send `POST /v1/analyze` with `{"sbom": <cyclonedx>}`; the output is the same.
2. **`/v1/resolve` returns only OpenVEX 0.2.0.** `format` is ignored; `source_format` and `match_reason` move into `status_notes`.
3. **`/v1/cve/{id}` returns OpenVEX 0.2.0**, and `204 No Content` when nothing matches (was `200` with an empty array).

### Added
- **`POST /v1/analyze`**: send an SBOM (annotated back), your own OpenVEX as `customer_vex` (merged back), or both.
- **Your statement overrides the vendor's** for one CVE and package (`match_reason=from_customer_vex`). Your VEX is never stored or logged.
- **Limits:** 5 MB; 10 user documents, 1000 statements, 100 products per statement; 50,000 components, 10,000 vulnerabilities. Over a limit or no input: `400`; invalid VEX: `422`.
- **Identical queries get identical `@id`s** (a content hash).

## [0.2.6] — Debian OVAL

*Released 2026-04-24*

### Added
- **Debian OVAL** for bullseye, bookworm and trixie: `fixed` with a fixed version, `affected` without.

## [0.2.5]

*Released 2026-04-23*

### Fixed
- **`/v1/resolve` matches deb rows**: `distro` is part of a package's identity; `arch`, `epoch` and `repository_id` are still ignored.

## [0.2.4]

*Released 2026-04-23*

**Upgrade notes:** In `config.yaml`, drop the `-oci` suffix from the Ubuntu OVAL adapter ids (`ubuntu-oval-noble`, `-jammy`, `-focal`) and point them at `com.ubuntu.<release>.usn.oval.xml.bz2`. State under the old ids is left in place.

### Changed
- **Ubuntu OVAL reads the main USN feeds**; the 0.2.3 OCI feeds yielded nothing.

## [0.2.3] — Ubuntu OVAL

*Released 2026-04-23*

### Added
- **Ubuntu OVAL** for focal, jammy and noble, `fixed` statements only (no data until 0.2.4).

## [0.2.2]

*Released 2026-04-21*

### Added
- **OpenVEX 0.2.0 output on `/v1/resolve`** with `"format": "openvex"`; an empty result is `204 No Content`.
- **`products[]` echoes the PURL you sent**, so Trivy applies statements Red Hat keyed on a CPE.

## [0.2.1]

*Released 2026-04-19*

### Added
- **An `api_request` log line per request** (`method`, `path`, `status`, `latency_ms`, `bytes`, and `cve` on `/v1/cve/{id}`), except `OPTIONS`.

## [0.2.0] — Red Hat OVAL

*Released 2026-04-19*

**Upgrade notes:** Add a Red Hat OVAL entry to `config.yaml`, and keep the CSAF entry's `id: redhat`. The schema migrates on first boot, with no full re-sync.

### Added
- **Red Hat OVAL** (`source_format` `oval`), for the EUS, AUS, E4S, SAP, HA and NFV streams CSAF lacks.
- **`source_formats` filter** on `/v1/resolve` (empty means all).

### Changed
- **`vendor` names the vendor, not the adapter**, so Red Hat OVAL rows say `redhat`.

## [0.1.7]

*Released 2026-04-17*

### Added
- **Aliases:** a PURL with `?repository_id=…` matches statements Red Hat keyed on that repository's CPE, with `match_reason` `via_alias`.
- **`aliases:` in `config.yaml`** (`type`, `id`, optional `url`), and an `aliases` count in `/v1/stats`.

## [0.1.6]

*Released 2026-04-17*

**Upgrade notes:** `config.yaml` changes from `providers:` to `adapters:`, each with a `type:`. The old form is no longer read.

```yaml
adapters:
  - type: csaf
    id: redhat
    name: Red Hat
    url: https://security.access.redhat.com/data/csaf/v2/provider-metadata.json
```

### Changed
- **`-limit` counts statements**, not documents.

## [0.1.5]

*Released 2026-04-17*

### Added
- **CPE prefix matching**: `cpe:/o:redhat:enterprise_linux:8::baseos` matches a statement keyed on `cpe:/o:redhat:enterprise_linux:8`.
- **`source_format`** on every statement and **`match_reason`** (`direct`, `via_cpe_prefix`) on each match.
- **Schema migrations run in place** on first boot.

### Fixed
- **A PURL with a version now matches.**
- **Red Hat CSAF advisories covering several streams yield CPE-keyed statements.**
