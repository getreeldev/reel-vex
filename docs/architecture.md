# reel-vex architecture

Deep-dive companion to the [README](../README.md). Covers the ingest pipeline, source-adapter framework, alias fetcher framework, version lists, sync strategy, removal, scheduling, and the on-disk project layout. For the API, see [`api.md`](./api.md). For the database schema, see [`data-model.md`](./data-model.md).

## Ingest pipeline

The pipeline is driven by `config.yaml`: a list of adapters (VEX feeds) and alias fetchers (identifier mapping files). Each adapter implements the same `source.Adapter` interface — `Discover`, then `Sync` — so the orchestrator (`pkg/ingest/ingest.go`) is format-agnostic.

### CSAF adapter

Each CSAF provider publishes a `provider-metadata.json` at a well-known URL. The adapter fetches it, finds the VEX distribution URL, and then takes one of two paths:

- **Cold start (no watermark)** — if the provider publishes a bulk archive (Red Hat's weekly `csaf_vex_<date>.tar.zst`, located via a sibling `archive_latest.txt`), the adapter downloads that single ~300 MB archive and walks it locally instead of fetching ~317K documents one HTTP GET at a time (minutes vs. hours). It then fetches only the post-archive delta from `changes.csv`. The archive's date — taken from the filename, or its `Last-Modified` header as a fallback — is the floor for that delta. Providers without such an archive (e.g. SUSE) fall back to crawling every document listed in `changes.csv`.
- **Incremental (have watermark)** — reads `changes.csv` and fetches only documents changed since the watermark.

Parsing uses [`gocsaf/csaf`](https://github.com/gocsaf/csaf) (the strict path) with a permissive map-based fallback for vendor feeds that violate CSAF 2.0 schema rules (SUSE's CPE 2.3 deviations, for example). Extracted per document:

- **Product IDs** from `product_tree.branches` (recursive walk) and `product_tree.relationships` (composite products). Both PURL and CPE identifiers, inherited from both sides of each relationship so platform CPEs end up on composite products.
- **CVE statuses** from `vulnerabilities[].product_status`: `not_affected`, `fixed`, `affected`, `under_investigation`. SUSE never writes `fixed`: it marks a fixed package `recommended` (older documents: `first_fixed`), and both are read as `fixed`.
- **Justifications** for `not_affected`: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`.

### OVAL adapters

Four OVAL adapters share the same fetch/parse flow: Ubuntu, Debian, AlmaLinux, and Oracle Linux. Each adapter instance fetches a single bz2-compressed OVAL XML file (one config entry per file/release). A `HEAD` check against `Last-Modified` short-circuits the GET when upstream hasn't regenerated the file. On a pull, the response is streamed through `compress/bzip2` and parsed via [`getreeldev/oval-to-vex`](https://github.com/getreeldev/oval-to-vex) — a dedicated OVAL-to-VEX translator library maintained alongside reel-vex, with per-vendor parsers (`FromUbuntuOVAL`, `FromDebianOVAL`, `FromAlmaLinuxOVAL`, `FromOracleOVAL`).

Ubuntu and Debian don't publish CSAF, so OVAL is the primary feed for those vendors. Ubuntu deb-shaped statements emit `pkg:deb/ubuntu/<name>?distro=ubuntu-<version>` PURLs; Debian emits `pkg:deb/debian/<name>?distro=debian-<N>`. The `distro` qualifier is part of identity — focal `openssl` and noble `openssl` are distinct products with different fix versions.

**AlmaLinux** and **Oracle Linux** are RHEL rebuilds whose OVAL carries RPM-level fix versions, so `oval-to-vex` gives them RPM-keyed parsers that walk the rpminfo criteria tree (emitting one `(name, fixed-evr)` per version test, dropping signature/arch/gate tests that carry no `<evr>`). AlmaLinux's release major comes from the `alsa-<N>` filename and is emitted under both `pkg:rpm/almalinux/` and `pkg:rpm/alma/` (scanner namespace drift); Oracle pairs each package with the release its version test is gated on (one ELSA can cover several majors), each Oracle adapter keeps only the rows of its own file's release (`ol<N>` in the URL; the adapter refuses to start without it), and Ksplice variants are skipped in v1.

### OpenVEX adapters

Two adapters consume OpenVEX 0.2.0 documents directly. **Ubuntu** (`ubuntu-vex`) walks Canonical's single `vex-all.tar.xz` tarball of per-CVE documents — a near-superset of the Ubuntu OVAL feed, adding pre-USN triage state — and skips the GET when `Last-Modified` has not moved. Canonical writes the `distro` qualifier in several shapes (`ubuntu/jammy`, `esm-infra/xenial`, `fips-updates/jammy`, and codename first, `trusty/esm`); the adapter rewrites each to the `ubuntu-<version>` scanners send, taking whichever segment is a known codename. **Rancher** (`rancher-vex`) ingests SUSE's Rancher VEX hub of `not_affected` suppressions for SUSE cloud-native product images (Rancher, RKE2, K3s, Harvester, Longhorn): it downloads the snapshot tarball the hub's `vex-repository.json` names (~8 MB, one commit) on every sync, and parses each per-package OpenVEX document the repository's `index.json` lists. Both emit exact-list rows (see [Version lists](#version-lists)).

Rancher statements are **product-scoped**, which is unique among the feeds. Each names a *product* (`products[].@id` — an OCI image or Go module) and the affected package as an OpenVEX *subcomponent*. The adapter stores the subcomponent as the queryable `product_id` / `base_id` and the product `@id` as the row's `scope` (normalised by `pkg/csaf.NormalizeScope` — `repository_url` kept, version/digest stripped). The same package can thus carry opposite verdicts under different images without colliding: `scope` is part of the `statements` primary key. The query layer gates on it — a scoped row is returned only when the caller supplies a matching scope, so a verdict scoped to one image never suppresses the same package elsewhere (see [`api.md`](./api.md#product-scoped-statements) and [`data-model.md`](./data-model.md)). Three statement classes are skipped at ingest: non-CVE-named statements (~3%, mostly `SUSE-SU` advisories with no CVE alias — reel-vex keys by CVE), any product carrying no subcomponent (which would imply an unscoped, global claim), and a subcomponent that is neither a PURL nor a CPE (Rancher's generator sometimes writes its own error text as the `@id`). The sync log counts them as `skipped_non_cve`, `skipped_no_subcomponent` and `skipped_bad_subcomponent`.

### Distro-database adapters

Two adapters consume vendor-native package databases that are neither OVAL nor OpenVEX. **Alpine** (`alpine-secdb`) fetches per-branch `main.json`/`community.json` from `secdb.alpinelinux.org` — a `{fixed-version: [CVE…]}` map per package; the `"0"` version key means the CVE does not apply to the package (emitted `not_affected`, `vulnerable_code_not_present`), every other key a `fixed` version. A CVE listed under several keys is one row: the highest fixed version by apk ordering, and `"0"` only when no fixed version lists it. **Amazon Linux** (`amazon-alas`) has no single feed file: it crawls each core repo's `mirror.list → repomd.xml → updateinfo.xml.gz` (the mirror base embeds a rotating GUID, re-resolved each run) and parses the RHSA-style `updateinfo` errata into `fixed` statements; v1 covers amzn2 + al2023 core repos.

These feeds — and the AlmaLinux/Oracle RPM rebuilds and Debian OVAL — store a major(.minor)-scoped `?distro=` identity, while scanners emit a more granular distro qualifier. `pkg/resolver` normalizes the query's qualifier down to the stored granularity (`amazon-2023.7.x → amazon-2023`, `alpine-3.21.2 → alpine-3.21`, `alma-9.1 → almalinux-9`, `debian-12.11 → debian-12`, `oracle-8.10 → oracle-8`) so a query matches without one release's fix leaking into another's scan; the rule is ecosystem-gated and additive.

### Version lists

A `statements` row is one verdict: one per (vendor, CVE, product identifier, source format, scope, stream, status, justification), carrying the sorted, de-duplicated list of versions the vendor stated for that verdict and a `version_kind` that says how the list is read ([`data-model.md`](./data-model.md)).

**Exact lists** (`version_kind = 'exact'`) are the two feeds whose versions name specific builds: Ubuntu OpenVEX (each binary's current archive version) and Rancher (the module version inside an image). Their adapters group what the vendor states by (CVE, identifier without its `@version` — every qualifier kept, scope, status, justification) and emit one row per group whose list is every version stated for it. For CVE-2024-1234 on Ubuntu 22.04 amd64:

| vendor states | rows |
|---|---|
| openssl 1.10 fixed, 1.11 fixed | `fixed [1.10, 1.11]` |
| zlib 1.2 not_affected, 1.3 not_affected | `not_affected [1.2, 1.3]` |
| curl 7.81 affected | `affected [7.81]` |
| glibc 2.35-1 affected, 2.35-2 fixed | `affected [2.35-1]` · `fixed [2.35-2]` |

A package listed without a version (every Rancher deb, rpm and apk subcomponent) gives an empty list, which matches any queried version. A rebuild changes a row's list instead of adding a row. The store replaces a list on upsert rather than merging it, so an adapter must emit each key once per sync with its complete list: both read their whole feed on every changed sync, and neither may gain an incremental path. On a later sync a version Canonical dropped leaves its list, a version whose verdict changed moves to the other row's list, and a verdict whose list empties is not emitted, so the whole-feed sweep deletes its row ([Removal](#removal)). No history of removed versions is kept.

A query is matched against these lists strictly — a versioned query gets only the verdict stated for that version, and nothing for a version the vendor did not list — and an exact row is rendered as per-version identifiers as the vendor published them ([`api.md`](./api.md#version-selection)).

**Every other feed** (`version_kind = ''`) still writes one version per statement, so its lists hold at most one element and it is matched and rendered as before 0.13. The OVAL feeds, Alpine and Amazon state fixed-in boundaries, and Red Hat and SUSE CSAF state a boundary per product stream; converting them to boundary lists compared in the distro's version ordering within the right stream (`version_kind = 'boundary'`, with `stream` in the key) is later work.

### Alias fetchers

Independent from VEX adapters. Each fetcher pulls a vendor-published mapping file and writes rows into `product_aliases`. The first implementation is Red Hat's `repository-to-cpe.json` — lets a scanner querying with a PURL carrying `?repository_id=rhel-8-for-x86_64-appstream-rpms` match VEX statements keyed on `cpe:/a:redhat:enterprise_linux:8::appstream`.

### Sync strategy

- **First run**: adapters seed their whole feed. Red Hat CSAF downloads its weekly bulk archive (~300 MB) and walks it locally — minutes, not the hours a ~313K-document per-file crawl would take. SUSE has no bulk archive, so it crawls its ~54K documents one at a time. OVAL is one bz2 file per adapter (seconds to minutes); Ubuntu's OpenVEX is a single tarball walk; Rancher's is a single ~8 MB snapshot tarball.
- **Incremental**: every adapter stores its own watermark in `adapter_state.last_synced`. CSAF adapters fetch only the documents `changes.csv` lists as changed since their watermark; the OVAL, Ubuntu OpenVEX and Alpine adapters HEAD the feed and skip the GET when `Last-Modified` has not moved. Amazon ALAS and Rancher re-read their whole feed every run.
- **Batch writes**: statements accumulate in memory and flush in batches of 5,000 — each batch is streamed into a temp table via Postgres `COPY`, then merged with a single set-based upsert that rewrites an existing row only when its version list, `base_id`, `id_type` or `version_kind` changed (a changed verdict is a different row). Every written row records its adapter in `adapter_id`, and each batch's keys are recorded for [removal](#removal).

### Removal

Ingest inserts and updates; removal deletes what a vendor no longer publishes. Each row records the adapter that last inserted or changed it (`statements.adapter_id`), and removal deletes only the running adapter's own rows, never another adapter's and never a row with no owner (one an earlier version stored).

While an adapter syncs, every key it emits — (CVE, product identifier, scope, stream, status, justification) — is recorded in a per-adapter seen table (`sweep_seen_<adapter>_<hash>`; UNLOGGED and without autovacuum, since batches land on different pool connections and the table is insert-only; dropped at the end of every run, and any a crashed process left behind are dropped when the next ingest cycle starts). After the sync the orchestrator deletes the adapter's rows it did not emit, by one of three mechanisms, chosen by what the adapter reports in its `SyncResult`:

| Mechanism | When | Deletes | Guard |
|---|---|---|---|
| **Whole-feed sweep** | The sync emitted the feed's entire current set (`Complete`): Ubuntu OpenVEX, every OVAL adapter and Alpine secdb when their file changed; Amazon ALAS and Rancher every run; a CSAF cold start with no document failed. | Every row the adapter owns that it did not emit. | Refused, deleting nothing, when it would delete more than `-sweep-max-fraction` of the rows the adapter owns, or when it emitted nothing. |
| **Per-document replacement** | CSAF documents fetched and fully parsed this run (`RefreshedCVEs`) on an incremental sync, including documents that now list nothing. | The adapter's rows of those CVEs that it did not emit. | None: a re-published CSAF document is the vendor's complete current set for its CVE, and can legitimately drop to nothing. |
| **Withdrawal** | Red Hat and SUSE CSAF, every run that read the distribution's `index.txt` (`LiveCVEs`), after the sweep or replacement. | Every row of each CVE the adapter holds that `index.txt` no longer lists. | Refused on an empty manifest, or when more than `-sweep-max-fraction` of the CVEs the adapter holds would be withdrawn. |

Red Hat's `deletions.csv` is not consumed: its dates are back-dated, SUSE publishes none, and some documents it lists are still in `index.txt` and served — the index wins.

Removal runs only when the sync can vouch for what it emitted. A Sync error, a failed batch write, or a run cut short by `-limit` removes nothing; a whole-file feed that found its file unchanged ("up to date, skipping GET") emitted nothing, so it is not complete and removes nothing either. A CSAF run in which some documents failed is not complete, but still replaces the documents it did read and still withdraws. A removal that fails or is refused is logged and never fails the adapter: the data was written, the watermark advances, and the next sync retries. Each sweep or withdrawal runs in one transaction bounded at two hours.

**`-sweep-max-fraction`** (default `0.2`, within `[0, 1]`) sets both fraction guards. `0` disables every removal mechanism and records no seen keys (rows still record their owner); `1` lifts the fraction guards, but a whole-feed sweep that saw nothing is still refused.

**Log lines.** Every adapter run logs exactly one `sweep` line, and a run that read `index.txt` also one `withdraw` line:

```
INFO sweep adapter=ubuntu-vex scope=all seen=195636880 owned=195702113 deleted=65233
INFO sweep adapter=redhat scope=cves:412 seen=38117 owned=40269 deleted=2152
INFO sweep adapter=debian-oval-bookworm scope=cves:0 seen=0 owned=0 deleted=0 skipped=incomplete
WARN sweep adapter=alpine-secdb-v3.21-main scope=all seen=5120 owned=7012 deleted=0 refused="would delete 1892 of 7012 owned rows (26.98%), over the 20.00% limit"
INFO withdraw adapter=redhat live=317412 held_cves=317425 withdrawn_cves=13 deleted=1844
```

`scope` is `all` for a whole-feed sweep and `cves:<n>` for the CVEs a CSAF run refreshed; `seen` counts keys emitted (duplicates included), `owned` the adapter's rows within scope. `skipped=incomplete` is the normal line for a feed that had not changed; the other `skipped` values are `disabled`, `sync error`, `flush error`, `limit`, `start error` and `aborted`. A refusal is a WARN with `deleted=0` and the reason; a failure is an ERROR with the error. The values above are illustrative.

**Disk.** A whole-feed sweep at Ubuntu scale (~196M rows) needs about 80 GB of transient disk: ~40 GB of hash-join temp files, ~17 GB for the adapter's materialised owned rows and ~23 GB of seen table — measured before the seen table gained the verdict columns, so a floor. All of it is released when the sweep ends. The sweep sets `temp_file_limit = '100GB'` only when its role is a superuser; a managed database's role cannot set it, so there the spill is bounded only by free disk. Deleted rows also write WAL (about one full page image each; `docker-compose.yml` sets `wal_compression=lz4`), and `statements` is autovacuumed at 1% of the table plus 100,000 rows so the freed space is reused after each sweep.

### Scheduling

The `serve` command runs ingest automatically on a configurable interval (default 24h). First ingest starts on boot. On-demand ingest is available via `POST /v1/ingest` (requires admin token).

## Project structure

```
reel-vex/
  cmd/server/main.go           -- entry point; registers adapters + fetchers
  pkg/
    csaf/                      -- CSAF 2.0 parsing primitives (strict + permissive)
      provider.go, feed.go, extract.go, extract_permissive.go, purl.go
    source/                    -- source-adapter framework
      adapter.go               -- Adapter interface
      config.go, registry.go   -- AdapterConfig + factory registry
      csafadapter/             -- CSAF adapter (wraps pkg/csaf; archive.go = bulk cold-start)
      ubuntuoval/              -- Ubuntu OVAL adapter (wraps oval-to-vex)
      debianoval/              -- Debian OVAL adapter (wraps oval-to-vex)
      almalinuxoval/           -- AlmaLinux OVAL adapter (wraps oval-to-vex)
      oracleoval/              -- Oracle Linux OVAL adapter (wraps oval-to-vex)
      ubuntuvex/               -- Canonical OpenVEX 0.2.0 adapter (tarball walk)
      ranchervex/              -- SUSE Rancher VEX hub adapter (product-scoped OpenVEX)
      alpinesecdb/             -- Alpine secdb adapter (per-branch JSON)
      amazonalas/              -- Amazon Linux ALAS adapter (repo updateinfo crawl)
    aliases/                   -- alias-fetcher framework
      aliases.go               -- Fetcher interface + registry
      redhat.go                -- Red Hat repository-to-cpe.json fetcher
    resolver/                  -- query-time identifier expansion
      cpe.go                   -- CPE 2.2 5-part prefix
      resolver.go              -- direct / via_alias / via_cpe_prefix
    ingest/ingest.go           -- orchestrator (adapters → statements; fetchers → aliases)
    db/                        -- Store interface + shared types (driver-agnostic)
      store.go, types.go
      postgres/                -- PostgreSQL backend (jackc/pgx): migrations.go, postgres.go, sweep.go
      dbtest/                  -- in-memory fake Store for tests
    api/                       -- HTTP handlers
      handler.go, analyze.go, gzip.go, ingest.go, request_log.go
  test/integration/api_test.go -- end-to-end tests (binary + DB + HTTP)
  test/acceptance/             -- acceptance suite: trimmed vendor feeds → ingest → exact HTTP answers
  testdata/                    -- fixtures: CSAF slices, OVAL fixture, alias sample
  config.yaml                  -- adapter + alias-fetcher configuration
  Dockerfile                   -- golang:1.27-alpine → alpine:3.24
```

**Companion library**: [`getreeldev/oval-to-vex`](https://github.com/getreeldev/oval-to-vex) — standalone Go library that parses Ubuntu, Debian, AlmaLinux, and Oracle Linux OVAL XML into VEX-shaped statements. Zero dependencies beyond stdlib. reel-vex's four OVAL adapters delegate to it; anyone else building scanners can `go get github.com/getreeldev/oval-to-vex/translator`.
