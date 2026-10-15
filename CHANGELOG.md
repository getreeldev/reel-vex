# Changelog

All notable changes to reel-vex. The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). reel-vex is pre-1.0, so a minor version can carry breaking changes; they are marked **Breaking** and listed under **Upgrade notes**.

## [0.13.1] — Ubuntu OpenVEX re-reads only the documents that changed

*Released 2026-10-15*

**Upgrade notes:** Rolls in place; no fresh database. The release adds one empty table, `adapter_documents`. If you roll back to 0.13.0 and later upgrade again, delete that table's rows first, or documents 0.13.0 rewrote in between can be skipped.

### Changed
- **Ubuntu OpenVEX syncs re-read only the documents that changed** since the last run, so a daily publish takes minutes instead of hours. Answers are the same. The first run after upgrading, and every run with removal off (`-sweep-max-fraction 0`), still reads the whole tarball.
- **A publish that changes more than a fifth of the documents, and more than 1,000,** is read whole and swept under `-sweep-max-fraction`. See [Removal](docs/architecture.md#removal).
- **Ubuntu OpenVEX now withdraws CVEs that leave the tarball** and logs a `withdraw` line, under the same guard.
- **To force a full read**, delete the adapter's rows from `adapter_documents`. The next run that fetches the tarball reads and sweeps it whole.
- **The adapter's watermark is now the tarball's `Last-Modified`.** It does not advance past a publish whose removal did not finish, so the next run (or a `-sweep-force` run) fetches it again.

## [0.13.0] — removal, version-aware answers, Debian by source package

*Released 2026-10-12*

**Upgrade notes:**
- **Start from an empty database.** Rows stored by an earlier version have no owner, so removal never deletes them, and the fixes below change which rows should exist. Let the first ingest load it.
- **`config.yaml` needs three edits** (the release's `config.yaml` has them):
  - Remove any `redhat-oval` entry. Otherwise the server does not boot (`unknown adapter type`).
  - Point `rancher-vex` at `https://github.com/rancher/vexhub/archive/refs/heads/main.tar.gz`. A URL still ending in `index.json` fails every Rancher sync.
  - Each `oracle-oval` URL must name a release file (`com.oracle.elsa-ol<N>.xml.bz2`). Otherwise the server does not boot (`cannot read the release from url`).
- **`/healthz` now answers `503 database unreachable` when the database does not answer a ping.** Used as a liveness probe, it restarts the app during a database outage.
- **Removal is on by default** (`-sweep-max-fraction 0.2`; `0` turns it off). A full sweep of Ubuntu OpenVEX needs up to ~116 GB of temporary disk on the database host.
- **Only one ingest runs per database.** A second `ingest` subcommand exits non-zero with `another ingest is running`. A `serve` scheduler logs the refusal and skips that run.
- **Breaking:** a query with a version can now get nothing where it used to get `fixed` (see Changed).
- **Breaking:** `/v1/analyze` leaves a vulnerability unannotated when its `affects[]` components disagree (see Changed).

### Changed
- **Breaking: a versioned query gets only the verdicts that hold for that version.** For Debian, Ubuntu OVAL, AlmaLinux, Oracle, Alpine and Amazon, `fixed` comes back only at or above the fixed-in version. For Ubuntu OpenVEX and Rancher, you get the verdict stated for that exact build, and nothing for a build the vendor did not list. Red Hat and SUSE CSAF are unchanged. See [Versioned queries](docs/api.md#versioned-queries).
- **Fixed-in rows answer a versioned query under the PURL you sent, version included.** Before, it was echoed in base form.
- **Ubuntu OpenVEX and Rancher answers name the vendor's own versioned identifiers**, one per matched build, written the way Trivy writes them (`epoch=N` qualifier, percent-encoded). A query without a version gets every listed build, each under its own verdict.
- **Breaking: `/v1/analyze` attributes verdicts per component.** A vulnerability whose `affects[]` components get different states is left without an analysis, instead of getting one rolled-up verdict. See [POST /v1/analyze](docs/api.md#post-v1analyze).
- **Ubuntu ESM/FIPS tracks of one release, and Rancher keys with conflicting justifications, return each verdict.** Before, the last one written won.
- **Red Hat CSAF can return several verdicts for one component**, one per product stream (for example `affected` on RHEL 6 and `not_affected` on RHEL 10). Before, only the last one was kept.
- **A changed verdict is a new row.** While removal is off, or refused for an adapter, the old and new verdicts are both served.
- **Rows that share an identifier come back in a fixed order**, so `offset` paging never repeats or skips one.
- **`limit`, `X-Reel-Statements` and `X-Reel-Truncated` count only the rows returned** after version matching.
- **Rancher is read from one repository snapshot per sync** instead of one request per file.
- **Red Hat and SUSE CSAF:** a document that fails is read again in the same run, and an HTTP 200 that is not the CSAF document counts as a failure. A cold start no longer stores an archived copy beside the current one.
- **The `adapter done` log line** carries `complete`, `refreshed` and `live`.
- Internal: a CSAF cold start returns ingest errors instead of falling back to a full crawl; acceptance suite; CI on every branch; `oval-to-vex` v0.4.0 and other dependency bumps; runtime image on Alpine 3.24; `docker-compose.yml` sets `wal_compression=lz4`.

### Added
- **Removal:** rows a vendor stops publishing are deleted after a sync, behind a safety guard. `-sweep-max-fraction` (default `0.2`; `0` off, `1` lifts the fraction guards) and `-sweep-force <adapter-id>[,…]` for a sweep that stays refused. See [Removal](docs/architecture.md#removal).
- **Debian binaries are answered from their source package** (`libc6` → `glibc`) on `/v1/analyze` and on `/v1/statements` with `sbom`, with `match_reason=via_source_package`. A plain `products` query must name the source package. See [Debian source packages](docs/api.md#debian-source-packages).
- **Alpine 3.24** feeds (`alpine-secdb-v3.24-main`, `alpine-secdb-v3.24-community`).

### Removed
- **Red Hat OVAL** (the `redhat-oval` adapter type). Red Hat is deprecating the feed. Queries against RHEL 9.6 EUS repository CPEs no longer get `fixed` for CVEs fixed before the 9.6 EUS branch point.

### Fixed
- **SUSE fixed packages are now stored as `fixed`.** None were before.
- **Alpine's `"0"` is now `not_affected`** (justification `vulnerable_code_not_present`), not `affected`. A package listed under several versions gets the highest fixed one.
- **Debian's `0:0` bound is now `affected`** with no version, not `fixed`.
- **Each Oracle Linux adapter stores only its own release.**
- **Ubuntu `trusty/esm` rows now match Ubuntu 14.04.**
- **Point-release distros now match**: `debian-12.11` reaches `debian-12`, `oracle-8.10` reaches `oracle-8`.
- **Amazon Linux `product_id`s are valid PURLs**, with the version before the qualifiers.
- **Red Hat rows loaded from the bulk archive carry each document's own date**, so `since` is right after a cold start.
- **Rancher error text is no longer stored as a product identifier.**
- **`match_reason` names the strongest rule**, whatever the order of the products sent.
- **Versionless npm-scoped PURLs** (`pkg:npm/@angular/core`) keep their name, and a PURL's subpath is dropped from its base form.
- **The echoed identifier keeps the caller's encoding** (`distro=amazon-2%20%28Karoo%29` is no longer decoded).

## [0.12.2] — the stats timeout now survives the process that set it

*Released 2026-08-24*

### Fixed
- **The `/v1/stats` time limit is enforced by Postgres**, so the computation stops even if the process that started it exits.
- **Browsers can read `Retry-After`** (added to `Access-Control-Expose-Headers`).

## [0.12.1] — /v1/stats no longer stalls after a restart

*Released 2026-08-24*

**Upgrade notes:** With the bundled `docker-compose.yml`, recreate the Postgres container to apply `shm_size: 1gb`.

### Changed
- **`/v1/stats` answers `503` with `Retry-After: 60` while its numbers are being computed**, instead of holding the request.
- **`shm_size: 1gb`** on the bundled Postgres service, which large parallel queries need.

### Fixed
- **`/v1/stats` is ready within minutes of a restart** instead of about half an hour.
- **The stats computation has a 20-minute limit.**

## [0.12.0] — OpenVEX statements grouped by assertion; opt-in architecture matching

*Released 2026-08-24*

**Upgrade notes:** If you count `statements[]`, the number changes (see Changed). No migration; to roll back, redeploy the previous image.

### Changed
- **Breaking for counters: statements are grouped.** Rows that agree on CVE, status, justification, supplier, timestamp and `status_notes` are one statement whose `products[]` lists all their products. Nothing is dropped, and Trivy suppresses the same findings. `X-Reel-Statements` still counts rows.

### Added
- **`strict_arch`** on `/v1/statements` and `/v1/analyze` (default `false`). When set, a row comes back only if it has no `arch`, an architecture-independent one (`noarch`, `src`, `source`, `all`), or one the request named.
- **`X-Reel-Grouped`** (statements emitted) and **`X-Reel-Arch`** (the architecture set `strict_arch` applied) headers. Browsers can read both.

### Fixed
- **Responses to queries with `products` are valid OpenVEX.** They used to contain duplicate statements.
- Internal: Go 1.27 toolchain, dependency updates, a full JSON Schema check in tests.

## [0.11.1] — telemetry: echo queried CVE for single-CVE lookups

*Released 2026-07-13*

### Added
- **`X-Reel-CVE` header** on `/v1/statements` when exactly one CVE was queried.

## [0.11.0] — telemetry: query mode + result size on response headers

*Released 2026-07-13*

### Added
- **`X-Reel-Mode`** (`cve` or `broad`) and **`X-Reel-Statements`** (statement count) headers on `/v1/statements` and `/v1/analyze`, on both `200` and `204`.

## [0.10.0] — four new OS feeds: Alpine, Amazon Linux, AlmaLinux, Oracle Linux

*Released 2026-06-09*

**Upgrade notes:** An adapter runs only when `config.yaml` lists it. Add the new entries to use these feeds (the release's `config.yaml` has them).

### Added
- **Alpine secdb** (`alpine-secdb`, vendor `alpine`, `source_format` `secdb`), per branch: `pkg:apk/alpine/<name>?distro=alpine-<major.minor>`. The secfixes `"0"` key was stored as `affected` (corrected to `not_affected` in 0.13.0).
- **Amazon Linux** (`amazon-alas`, vendor `amazon`, `source_format` `updateinfo`) for the amzn2 and al2023 core repositories.
- **AlmaLinux and Oracle Linux OVAL** (`almalinux-oval`, `oracle-oval`). AlmaLinux rows are emitted under both `pkg:rpm/almalinux/` and `pkg:rpm/alma/`.
- **Distro normalisation for these feeds**: `alpine-3.21.2` → `alpine-3.21`, `amazon-2023.7.x` → `amazon-2023`, `almalinux-9.1` → `almalinux-9`.

## [0.9.2] — analyze CVE cap raised to the SBOM limit (covering index made it cheap)

*Released 2026-06-07*

**Upgrade notes:** The bundled `docker-compose.yml` now refuses to start until `ADMIN_TOKEN` is set in `.env` (see `.env.example`). It gates `POST /v1/ingest`.

### Changed
- **`-analyze-max-cves` defaults to 10000** (was 500), the same as `-max-sbom-vulns`. Requests that got a `400` may now be accepted.
- **`docker-compose.yml`** runs `-ingest-interval 4h` and `-admin-token`, and pins the image tag.

## [0.9.1] — build the covering index after the cold load (fast first deploy)

*Released 2026-06-05*

### Changed
- **The broad-mode covering index is built after each ingest**, not by the migration, so loading an empty database is fast. A 0.9.0 database keeps its index.

## [0.9.0] — Postgres backend; SQLite removed (BREAKING)

*Released 2026-06-05*

**Upgrade notes:** **Breaking:** reel-vex needs PostgreSQL. `-db` takes a `postgres://` URL instead of a file path. Nothing is imported from SQLite; the first ingest fills the new database.

### Added
- **`-no-scheduler`**: serve without the in-process ingest, for read-only replicas beside a separate `ingest` worker.
- **`docker-compose.yml` and `.env.example`**: the app plus Postgres, with `config.yaml` mounted from the host.

### Removed
- **The SQLite backend.**
- Internal: bulk loading with `COPY`; tests run against an in-memory store.

## [0.8.5] — every bounding limit is now a host flag

*Released 2026-06-05*

### Added
- **Five limit flags**, with the previous values as defaults: `-query-timeout` (20s), `-max-sbom-components` (50000), `-max-sbom-vulns` (10000), `-max-statements-items` (10000), `-max-user-vex-statements` (25000).
- **The HTTP write timeout follows `-query-timeout`** (`max(30s, query-timeout + 10s)`).
- Internal: a `db.Store` interface between the database and the rest.

## [0.8.4] — skip the boot-time ingest when data is fresh

*Released 2026-06-02*

### Changed
- **A restart runs an ingest only when the data is stale** (the last cycle is at least one interval old). Otherwise the next run waits until one interval after the last. The first restart after upgrading ingests once. `POST /v1/ingest` still forces a run.

## [0.8.3] — make the /v1/analyze CVE cap a host flag

*Released 2026-06-02*

### Changed
- **`-analyze-max-cves` flag** sets the `/v1/analyze` CVE cap. The default is 500 (was a fixed 800).

## [0.8.2] — calibrate the /v1/analyze cap to measured query cost

*Released 2026-06-02*

### Changed
- **`/v1/analyze` CVE cap 1000 → 800, and the statement query timeout 15 s → 20 s.**

## [0.8.1] — bound /v1/analyze query cost

*Released 2026-06-02*

### Changed
- **`/v1/analyze` answers `400` when a request would query more than 1000 distinct CVEs.** Split the document or narrow it.
- **Every statement query has a 15 s database timeout.** A query that hits it answers `503`.

## [0.8.0] — accept CycloneDX VEX on upload (normalised to OpenVEX)

*Released 2026-06-02*

### Added
- **`user_vex` accepts CycloneDX VEX**, converted to OpenVEX. A converted statement records `converted_from=cyclonedx-vex`, its original justification and `fidelity` in `status_notes`.
- **`reject_cyclonedx_lossy`** (default `false`) drops statements whose conversion is not exact.
- **`X-Reel-Converted` header** with converted, lossy, contested and skipped counts.

### Changed
- **A malformed user-VEX statement is skipped and counted**, instead of failing the request. Numeric limits still answer `400`.
- **User-VEX statement cap 1000 → 25000.**
- **An OpenVEX document that uses CycloneDX words is converted, not rejected** (reverses 0.7.1).

## [0.7.1] — user-VEX format detection, larger upload cap, rancher-vex hardening

*Released 2026-06-02*

### Changed
- **`-sbom-max-mb` defaults to 10** (was 5), on `/v1/analyze` and `/v1/statements`.
- **An OpenVEX document that uses CycloneDX words** (`requires_environment`, `in_triage`, …) is rejected with one clear "this is CycloneDX" error.

### Fixed
- **Rancher statements carry the document's timestamp** instead of the ingest time, so `since` filters them correctly.
- **Rancher incremental syncs no longer drop files** past GitHub's 300-file compare limit.

## [0.7.0] — report server version in /v1/stats

*Released 2026-05-27*

### Added
- **`version` in `/v1/stats`**: the server build, or `dev` for local builds.

## [0.6.4] — rancher-vex consumes the index.json repo format

*Released 2026-05-27*

**Upgrade notes:** In `config.yaml`, change the `rancher-vex` URL from `…/reports/rancher.openvex.json` to `…/refs/heads/main/index.json`.

### Changed
- **Rancher is read file by file through its `index.json`**, and later syncs fetch only the files that changed. This returns more Rancher statements than the consolidated document did.

## [0.6.3] — skip rewriting unchanged statements on ingest

*Released 2026-05-27*

### Changed
- **Ingest rewrites a row only when its verdict changed.** `updated`, and so `since`, now tracks the last real change rather than the last re-publish.

## [0.6.2] — retry transient feed-fetch failures

*Released 2026-05-27*

### Added
- **Feed downloads retry transient failures** (network errors, `429`, `500`, `502`, `503`, `504`) up to 3 times with backoff.

## [0.6.1] — expose truncation headers to browsers

*Released 2026-05-27*

### Fixed
- **Browsers can read `X-Reel-Truncated` and `X-Reel-Next-Offset`** (added to `Access-Control-Expose-Headers`).

## [0.6.0] — SUSE Rancher VEX hub (product-scoped statements)

*Released 2026-05-26*

**Upgrade notes:** A forward-only migration adds `scope` to the `statements` primary key and rewrites the table. To roll back, restore a backup taken before the upgrade. Add the `rancher-vex` entry to `config.yaml` to ingest the feed.

### Added
- **SUSE Rancher VEX hub** (`rancher-vex`, vendor `rancher`): `not_affected` verdicts scoped to Rancher product images. Statements with no CVE id (mostly `SUSE-SU` advisories) are skipped. See [Product-scoped statements](docs/api.md#product-scoped-statements).
- **`scopes` on `/v1/statements`.** A scoped verdict comes back only when you name its scope. An SBOM's `metadata.component` supplies it on both endpoints, and scoped rows carry `scope=` in `status_notes`. Without a scope, answers are unchanged.

## [0.5.1] — broad-mode queries, `/v1/analyze` synthesis, faster ingest

*Released 2026-05-26*

### Added
- **Broad mode on `/v1/statements`**: products or SBOM components with no CVEs return every statement for those products. Only a request with neither CVEs nor products is a `400`.
- **`-statements-max`** (default 50000, `0` = unlimited) caps `/v1/statements`. A capped answer is still `200`, with `X-Reel-Truncated: true` and `X-Reel-Next-Offset`. Page with `limit` and `offset`.
- **gzip responses** when the request sends `Accept-Encoding: gzip` (not on `204` or `304`).
- **Red Hat CSAF loads from the weekly bulk archive** on a cold start, so filling an empty database takes minutes instead of hours.

### Changed
- **`/v1/analyze` fills in an SBOM with no `vulnerabilities`** from a broad-mode lookup, then annotates them. Before, such an SBOM came back unchanged.
- **Results come back in a fixed order**, so paged and cached output is stable.
- **The empty-input error** now reads `one of cves, products, or sbom (with components or vulnerabilities) is required`.

## [0.5.0] — `/v1/statements` accepts SBOM input

*Released 2026-05-03*

### Added
- **`sbom` on `/v1/statements`**: CVEs come from `vulnerabilities[].id` and products from `components[].purl` and `.cpe`, merged with any `cves` or `products` you send. `cves` is optional when `sbom` is given.
- **`-sbom-max-mb`** (default 5) caps the body on `/v1/analyze` and `/v1/statements`.

### Changed
- **The `/v1/statements` body cap is 5 MB** (was 1 MB).
- **The empty-input error** now reads `one of cves or sbom (with vulnerabilities) is required`.

## [0.4.4] — `/v1/analyze` emits BOM-Link refs

*Released 2026-05-03*

### Changed
- **`/v1/analyze` writes `affects[].ref` as a BOM-Link** (`urn:cdx:<serial>/<version>#<bom-ref>`), so `trivy sbom --vex` applies the result. A ref stays as sent when the SBOM lacks `serialNumber`, `version` or the component's `bom-ref`.

## [0.4.3] — Resolver bridge for scanner-emitted RPM `?distro=` qualifiers

*Released 2026-05-03*

### Fixed
- **An RPM PURL with `?distro=`, as Trivy and syft write it, now also matches Red Hat rows stored without it**, on `/v1/analyze` and `/v1/statements`.

## [0.4.2] — Canonical OpenVEX adapter

*Released 2026-05-02*

**Upgrade notes:** Add the `ubuntu-vex` entry to `config.yaml` to ingest the feed.

### Added
- **Canonical OpenVEX** (`ubuntu-vex`, `source_format` `openvex`), including Canonical's triage before a USN (`not_affected`, `under_investigation`). Ubuntu OVAL stays alongside it, because each covers package names the other spells differently.

### Changed
- **`/v1/stats` is served from a cache** that is refreshed after each ingest and warmed at startup.

## [0.4.1] — rename `customer_vex` → `user_vex`

*Released 2026-04-27*

**Upgrade notes:** **Breaking rename**, no change in behaviour:

| Old | New |
|---|---|
| `customer_vex` on `POST /v1/analyze` | `user_vex` |
| `match_reason=from_customer_vex` in `status_notes` | `match_reason=from_user_vex` |
| Go package `pkg/customervex` | `pkg/uservex` |

A request that still sends `customer_vex` gets `400` (`at least one of sbom or user_vex required`).

### Changed
- **`customer_vex` is now `user_vex`**, and `from_customer_vex` is now `from_user_vex`.

## [0.4.0] — unified `/v1/statements` query endpoint

*Released 2026-04-27*

**Upgrade notes:** **Breaking.** Three routes now answer `404`:

| Old | New |
|---|---|
| `GET /v1/cve/{id}` | `POST /v1/statements` with `{"cves": ["<id>"]}` |
| `GET /v1/cve/{id}/summary` | none |
| `POST /v1/resolve` | `POST /v1/statements` with the same body |

### Added
- **`POST /v1/statements`**, with new filters `vendors`, `statuses`, `justifications` and `since` beside `source_formats`. Filters combine with AND, and the values in one filter with OR. `cves` is required (relaxed in 0.5.0). See [POST /v1/statements](docs/api.md#post-v1statements).

### Removed
- **`GET /v1/cve/{id}`, `GET /v1/cve/{id}/summary` and `POST /v1/resolve`.**

## [0.3.0] — API format unification + user-VEX merge

*Released 2026-04-27*

**Upgrade notes:** **Breaking**, three changes:
1. **`POST /v1/sbom` is removed** (`404`). Send `POST /v1/analyze` with `{"sbom": <cyclonedx>}`. The output is the same.
2. **`/v1/resolve` returns only OpenVEX 0.2.0.** The `format` field is ignored. `source_format` and `match_reason` move into `status_notes`.
3. **`/v1/cve/{id}` returns OpenVEX 0.2.0**, and `204 No Content` when nothing matches (was `200` with an empty array).

### Added
- **`POST /v1/analyze`** takes an SBOM, your own OpenVEX documents (`customer_vex`, renamed `user_vex` in 0.4.1), or both. An SBOM comes back as annotated CycloneDX. VEX alone comes back as merged OpenVEX. Your statement overrides the vendor's for the same CVE and package. Your VEX is never stored or logged.
- **Limits on `/v1/analyze`:** 5 MB body; 10 user documents, 1000 user statements and 100 products per statement; 50,000 SBOM components and 10,000 vulnerabilities. A limit or missing input answers `400`; an invalid VEX document answers `422`.
- **`match_reason=from_customer_vex`** (now `from_user_vex`) on your own statements.
- **A document's `@id` is a hash of its content**, so identical queries get identical `@id`s.

### Removed
- **`POST /v1/sbom`, the `format` field and the native response shape.**

## [0.2.6] — Debian OVAL adapter

*Released 2026-04-24*

### Added
- **Debian OVAL** for bullseye, bookworm and trixie, as `pkg:deb/debian/<name>?distro=debian-<N>`. A definition with a fixed version is `fixed`; one without is `affected`.

## [0.2.5] — preserve `distro` qualifier on PURL base IDs

*Released 2026-04-23*

### Fixed
- **`/v1/resolve` now matches Ubuntu and other deb rows.** The `distro` qualifier is kept as part of the package's identity. `arch`, `epoch` and `repository_id` are still ignored.

## [0.2.4] — switch Ubuntu adapters to main USN feeds

*Released 2026-04-23*

**Upgrade notes:** In `config.yaml`, the Ubuntu OVAL adapter ids lose their `-oci` suffix (`ubuntu-oval-noble`, `ubuntu-oval-jammy`, `ubuntu-oval-focal`) and point at the main USN feeds (`com.ubuntu.<release>.usn.oval.xml.bz2`). State stored under the old ids is left in place.

### Changed
- **Ubuntu OVAL reads the main USN feeds.** The OCI feeds used in 0.2.3 yielded no statements.

## [0.2.3] — Ubuntu OVAL adapter

*Released 2026-04-23*

### Added
- **Ubuntu OVAL** for focal, jammy and noble, as `pkg:deb/ubuntu/<name>?distro=ubuntu-<version>`, with `fixed` statements only. The OCI feeds configured here yielded nothing until 0.2.4.

## [0.2.2] — OpenVEX opt-in output + native format as first-class

*Released 2026-04-21*

### Added
- **OpenVEX 0.2.0 output on `/v1/resolve`** with `"format": "openvex"` (native JSON stays the default). An empty OpenVEX result is `204 No Content`.
- **`products[]` echoes the PURL you sent**, so Trivy can apply a statement Red Hat keyed on a CPE.
- **`docs/api.md`**, the API reference.

## [0.2.1]

*Released 2026-04-19*

### Added
- **One `api_request` log line per request** with `method`, `path`, `status`, `latency_ms` and `bytes`, plus `cve` on `/v1/cve/{id}`. `OPTIONS` preflight requests are not logged.

## [0.2.0] — multi-source Red Hat coverage

*Released 2026-04-19*

**Upgrade notes:** Add a Red Hat OVAL entry to `config.yaml`, and keep the CSAF entry's `id: redhat`. The schema migrates on first boot and keeps the CSAF watermark, so there is no full re-sync.

### Added
- **Red Hat OVAL** (`source_format` `oval`), covering the EUS, AUS, E4S, SAP, HA and NFV streams that CSAF lacks.
- **`source_formats` filter** on `/v1/resolve` (for example `["csaf", "oval"]`; empty means all).

### Changed
- **`vendor` names the vendor, not the adapter**, so Red Hat OVAL rows say `redhat`.

## [0.1.7]

*Released 2026-04-17*

### Added
- **Identifier aliases.** A PURL with `?repository_id=…` matches statements Red Hat keyed on that repository's CPE, through Red Hat's `repository-to-cpe.json`. New `match_reason` value `via_alias`.
- **`aliases:` section in `config.yaml`** (`type`, `id`, optional `url`).
- **`aliases` count in `/v1/stats`.**

## [0.1.6]

*Released 2026-04-17*

**Upgrade notes:** `config.yaml` changes from `providers:` to `adapters:`, and each entry needs a `type:`. The old form is no longer read.

```yaml
adapters:
  - type: csaf
    id: redhat
    name: Red Hat
    url: https://security.access.redhat.com/data/csaf/v2/provider-metadata.json
```

### Changed
- **`-limit` counts statements**, not documents.
- Internal: each feed is read through a common adapter interface; a scheduled ingest stops cleanly on shutdown.

## [0.1.5]

*Released 2026-04-17*

### Added
- **CPE prefix matching** on `/v1/resolve` and `/v1/sbom`: `cpe:/o:redhat:enterprise_linux:8::baseos` matches a statement keyed on `cpe:/o:redhat:enterprise_linux:8`.
- **`source_format`** on every statement, and **`match_reason`** (`direct`, `via_cpe_prefix`) on each match.
- **Schema migrations run in place on first boot**, keeping existing rows.

### Fixed
- **A PURL with a version now matches.** Stored package identifiers no longer carry the vendor's version.
- **Red Hat CSAF advisories that cover several streams now yield CPE-keyed statements.**
