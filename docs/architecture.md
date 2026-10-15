# reel-vex architecture

Deep-dive companion to the [README](../README.md). Covers the ingest pipeline, source-adapter framework, alias fetcher framework, version lists, sync strategy, removal, scheduling, and the on-disk project layout. For the API, see [`api.md`](./api.md). For the database schema, see [`data-model.md`](./data-model.md).

## Ingest pipeline

The pipeline is driven by `config.yaml`: a list of adapters (VEX feeds) and alias fetchers (identifier mapping files). Each adapter implements the same `source.Adapter` interface — `Discover`, then `Sync` — so the orchestrator (`pkg/ingest/ingest.go`) is format-agnostic.

### CSAF adapter

Each CSAF provider publishes a `provider-metadata.json` at a well-known URL. The adapter fetches it, finds the VEX distribution URL, and then takes one of two paths:

- **Cold start (no watermark)** — the adapter reads `changes.csv` and the distribution's `index.txt` (the list of every live document) first, back to back, so the two describe one moment of the feed, and then reads each document once. If the provider publishes a bulk archive (Red Hat's weekly `csaf_vex_<date>.tar.zst`, located via a sibling `archive_latest.txt`), it downloads that single ~300 MB archive and walks it locally instead of fetching Red Hat's ~69.9K documents one HTTP GET at a time (minutes vs. hours). The archive is a weekly cut, so the walk skips every document `changes.csv` dates after the cut (the archive's date comes from its filename, or its `Last-Modified` header as a fallback) and every document `index.txt` no longer lists. The crawl then reads every `changes.csv` document the archive did not — the post-cut delta, or everything after the point a broken archive failed — and finally each `index.txt` document neither read, by its index path, dated by its own `current_release_date`. Providers without an archive (SUSE, ~70.1K documents) crawl it all. A cold start is complete only when `index.txt` was read and trusted (below), every document it lists was read, and no document failed.
- **Incremental (have watermark)** — reads `changes.csv` and fetches only documents changed since the watermark, and reads `index.txt` for [withdrawal](#removal).

Every fetched body must be the CSAF document its path names — a `document.csaf_version`, a `document.tracking.id`, and the CVE as the tracking id or in `vulnerabilities[].cve` — so an HTTP 200 carrying an error page or an empty object is a failed read, not a document that states nothing. A document that answers 404 or 410 and that `index.txt` does not list was withdrawn after `changes.csv` named it, and is not a failure. Every other failed document is read once more about 30 s after the main pass; one that fails again makes the run incomplete and, for a `changes.csv` document, holds the watermark one second before the earliest such document, so the next run reads it again — unless its `changes.csv` date is more than 7 days old, when it is given up on with a WARN (the vendor re-publishing it lists it in `changes.csv` again). An `index.txt` that lacks a document this run fetched from the feed is not trusted as the list of live documents: the run logs a WARN, withdraws nothing, and is not complete.

These steps log `csaf reading failed documents once more`, `csaf failed documents read once more` (with `retried` and `recovered`) and `csaf document withdrawn: gone, and index.txt does not list it` at INFO, and `csaf document gone but not withdrawn`, `csaf document failed and is older than the retry window; giving up on it` and `csaf index.txt lacks documents fetched this run; no live manifest this run` at WARN.

Parsing uses [`gocsaf/csaf`](https://github.com/gocsaf/csaf) (the strict path) with a permissive map-based fallback for vendor feeds that violate CSAF 2.0 schema rules (SUSE's CPE 2.3 deviations, for example). Extracted per document:

- **Product IDs** from `product_tree.branches` (recursive walk) and `product_tree.relationships` (composite products). Both PURL and CPE identifiers, inherited from both sides of each relationship so platform CPEs end up on composite products.
- **CVE statuses** from `vulnerabilities[].product_status`: `not_affected`, `fixed`, `affected`, `under_investigation`. SUSE never writes `fixed`: it marks a fixed package `recommended` (older documents: `first_fixed`), and both are read as `fixed`.
- **Justifications** for `not_affected`, from the document's flags, passed through verbatim: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.

### OVAL adapters

Four OVAL adapters share the same fetch/parse flow: Ubuntu, Debian, AlmaLinux, and Oracle Linux. Each adapter instance fetches a single bz2-compressed OVAL XML file (one config entry per file/release). A `HEAD` check against `Last-Modified` short-circuits the GET when upstream hasn't regenerated the file. On a pull, the response is streamed through `compress/bzip2` and parsed via [`getreeldev/oval-to-vex`](https://github.com/getreeldev/oval-to-vex) — a dedicated OVAL-to-VEX translator library maintained alongside reel-vex, with per-vendor parsers (`FromUbuntuOVAL`, `FromDebianOVAL`, `FromAlmaLinuxOVAL`, `FromOracleOVAL`).

Ubuntu and Debian don't publish CSAF, so OVAL is the primary feed for those vendors. Ubuntu deb-shaped statements emit `pkg:deb/ubuntu/<name>?distro=ubuntu-<version>` PURLs; Debian emits `pkg:deb/debian/<name>?distro=debian-<N>`. The `distro` qualifier is part of identity — focal `openssl` and noble `openssl` are distinct products with different fix versions.

**AlmaLinux** and **Oracle Linux** are RHEL rebuilds whose OVAL carries RPM-level fix versions, so `oval-to-vex` gives them RPM-keyed parsers that walk the rpminfo criteria tree (emitting one `(name, fixed-evr)` per version test, dropping signature/arch/gate tests that carry no `<evr>`). AlmaLinux's release major comes from the `alsa-<N>` filename and is emitted under both `pkg:rpm/almalinux/` and `pkg:rpm/alma/` (scanner namespace drift); Oracle pairs each package with the release its version test is gated on (one ELSA can cover several majors), each Oracle adapter keeps only the rows of its own file's release (`ol<N>` in the URL; the adapter refuses to start without it), and Ksplice variants are skipped in v1. Each adapter trusts its own release's file, and the files do not always agree: ELSA-2026-500137 in the ol8 file names 19 OL9 packages that the ol9 file's copy of the advisory lacks, so those packages get no OL9 `fixed` row.

### OpenVEX adapters

Two adapters consume OpenVEX 0.2.0 documents directly. **Ubuntu** (`ubuntu-vex`) walks Canonical's single `vex-all.tar.xz` tarball of per-CVE documents — broader than the Ubuntu OVAL feed and carrying pre-USN triage state, though neither feed is a superset of the other: OVAL covers identifier shapes OpenVEX spells differently, which is why both are kept — and skips the GET when `Last-Modified` has not moved. One `Last-Modified` covers ~70K documents and Canonical publishes no list of what changed, while a publish typically changes about a hundred (between the 2026-10-14 and 2026-10-15 tarballs, 130 of 69,923 documents changed, 30 of them in what they state), so the adapter fingerprints every document (SHA-256 of its bytes) and emits only those whose fingerprint differs from the last run's, each one whole; the orchestrator replaces just those CVEs' rows (see [Removal](#removal)). The fingerprints live in `adapter_documents`. Leaving a document out leaves out exactly its CVE's rows only while each file is one CVE's own, which Canonical's are; a tarball with two files of one name, or a document naming another CVE, is read whole from the buffered copy, swept whole, and keeps no fingerprints. So is a publish that changed more than a fifth of the documents and more than 1,000 of them (a format the parser reads as empty would otherwise replace every CVE's rows with nothing, unguarded); it keeps its fingerprints. A whole read that skipped a document (malformed, or over 256 MiB) removes nothing and keeps no fingerprints, as every read did before documents were left out. Changing what a document emits means bumping `fingerprintVersion` in the adapter, which makes the next run read everything. Canonical writes the `distro` qualifier in several shapes (`ubuntu/jammy`, `esm-infra/xenial`, `fips-updates/jammy`, and codename first, `trusty/esm`); the adapter rewrites each to the `ubuntu-<version>` scanners send, taking whichever segment is a known codename. **Rancher** (`rancher-vex`) ingests SUSE's Rancher VEX hub of `not_affected` suppressions for SUSE cloud-native product images (Rancher, RKE2, K3s, Harvester, Longhorn): it downloads the snapshot tarball the hub's `vex-repository.json` names (~8 MB, one commit) on every sync, and parses each per-package OpenVEX document the repository's `index.json` lists. Both emit exact-list rows (see [Version lists](#version-lists)).

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

A query is matched against these lists strictly — a versioned query gets only the verdict stated for that version, and nothing for a version the vendor did not list — and an exact row is rendered as one identifier per matched version, written as Trivy writes the package: a deb or rpm version with an inline epoch loses it, is percent-encoded, and gains an `epoch=N` qualifier (`bind9@9.11.3%2Bdfsg-1ubuntu1.17?arch=amd64&distro=ubuntu-18.04&epoch=1`) ([`api.md`](./api.md#version-selection)).

**The OVAL feeds, Alpine and Amazon** state `fixed` with a fixed-in version, and write such a row with `version_kind = 'boundary'` and that one version: a versioned query gets it only at or above the version, compared in the distro's ordering (dpkg, rpm, apk) as the store reads the rows, and it is answered under the query's own versioned identifier ([`api.md`](./api.md#fixed-in-versions-boundary-rows)). A key stated with several fixed-in versions (parallel streams) still keeps the last one written — 5,967 such keys in Debian bookworm's OVAL, and Oracle's UEK and AlmaLinux's module streams have them too — so a version the vendor fixed in another stream may get no answer; the rule can only remove a `fixed` answer 0.12 gave, never add one. **Red Hat and SUSE CSAF** (`version_kind = ''`) still write one version per statement and are matched and rendered as before 0.13: they state a boundary per product stream, and comparing it within the right stream (with `stream` in the key) is later work.

### Alias fetchers

Independent from VEX adapters. Each fetcher pulls a vendor-published mapping file and writes rows into `product_aliases`. The first implementation is Red Hat's `repository-to-cpe.json` — lets a scanner querying with a PURL carrying `?repository_id=rhel-8-for-x86_64-appstream-rpms` match VEX statements keyed on `cpe:/a:redhat:enterprise_linux:8::appstream`.

### Sync strategy

- **First run**: adapters seed their whole feed. Red Hat CSAF downloads its weekly bulk archive (~300 MB) and walks it locally — minutes, not the hours a ~69.9K-document per-file crawl would take. SUSE has no bulk archive, so it crawls its ~70.1K documents one at a time. OVAL is one bz2 file per adapter (seconds to minutes); Ubuntu's OpenVEX is a single tarball walk; Rancher's is a single ~8 MB snapshot tarball.
- **Incremental**: every adapter stores its own watermark in `adapter_state.last_synced`. CSAF adapters fetch only the documents `changes.csv` lists as changed since their watermark; the OVAL, Ubuntu OpenVEX and Alpine adapters HEAD the feed and skip the GET when `Last-Modified` has not moved, and when it has, Ubuntu OpenVEX emits only the documents whose fingerprint changed and records the tarball's `Last-Modified` as its watermark (every other adapter records the newest statement date it emitted). Amazon ALAS and Rancher re-read their whole feed every run.
- **Batch writes**: statements accumulate in memory and flush in batches of 5,000 — each batch is streamed into a temp table via Postgres `COPY`, then merged with a single set-based upsert that rewrites an existing row only when its version list, `base_id`, `id_type` or `version_kind` changed (which also moves `updated`), or when another adapter owns it (which moves only `adapter_id`). A changed verdict is a different row. Every written row records its adapter in `adapter_id`, and each batch's keys are recorded for [removal](#removal).

### Removal

Ingest inserts and updates; removal deletes what a vendor no longer publishes. Each row belongs to the adapter that last wrote it (`statements.adapter_id`): an identical write by another adapter moves only the owner, so when two adapters emit one key (an Alpine package that moved between the main and community repositories) and the first stops, its sweep cannot delete a row the other still publishes. Removal deletes only the running adapter's own rows, never another adapter's and never a row with no owner (one an earlier version stored).

**One ingest at a time.** `ingest.Run` holds a Postgres session-level advisory lock for its whole run. A second ingest against the same database — a CronJob running the `ingest` subcommand while a `serve` scheduler is mid-run, or a manual `ingest` beside `serve` — touches nothing and refuses with `another ingest is running`; otherwise it would replace the running ingest's seen keys mid-sync, and that ingest's sweep would then delete live rows. Only once the lock is held does a run drop the seen tables a crashed process left behind.

While an adapter syncs, every key it emits — (CVE, product identifier, scope, stream, status, justification) — is recorded in a per-adapter seen table (`sweep_seen_<adapter>_<hash>`; UNLOGGED and without autovacuum, since batches land on different pool connections and the table is insert-only; dropped at the end of every run, and any a crashed process left behind are dropped when the next ingest cycle starts). After the sync the orchestrator deletes the adapter's rows it did not emit, by one of three mechanisms, chosen by what the adapter reports in its `SyncResult`:

| Mechanism | When | Deletes | Guard |
|---|---|---|---|
| **Whole-feed sweep** | The sync emitted the feed's entire current set (`Complete`): every OVAL adapter and Alpine secdb when their file changed; Ubuntu OpenVEX when it read every document (its first run, once its fingerprints are cleared, or a publish that changed more than a fifth of the documents and more than 1,000); Amazon ALAS and Rancher every run; a CSAF cold start that read every document its trusted `index.txt` lists, with none failed. | Every row the adapter owns that it did not emit. | Refused, deleting nothing, when it would delete more than `-sweep-max-fraction` of the rows the adapter owns, or when it emitted nothing. |
| **Per-document replacement** | Documents fetched and fully parsed this run (`RefreshedCVEs`), including documents that now list nothing, on a run that is not complete: a CSAF incremental sync or a cold start in which some documents failed, and an Ubuntu OpenVEX run's changed documents. | The adapter's rows of those CVEs that it did not emit. | None: a re-published document is the vendor's complete current set for its CVE, and can legitimately drop to nothing. Ubuntu OpenVEX bounds how many CVEs one run replaces this way: a larger publish is read whole, for the guarded whole-feed sweep. |
| **Withdrawal** | Red Hat and SUSE CSAF, every run that read and trusted the distribution's `index.txt` (`LiveCVEs`), and Ubuntu OpenVEX, every run that left a document out (`LiveCVEs` is every CVE in the tarball), whose removal was not skipped, after the sweep or replacement. | Every row of each CVE the adapter holds that is neither in the manifest nor among the documents this run refreshed (a document fetched from the feed is live even when `index.txt`, read at another moment, does not list it yet). | Refused on an empty manifest, or when more than `-sweep-max-fraction` of the CVEs the adapter holds would be withdrawn. |

Red Hat's `deletions.csv` is not consumed: its dates are back-dated, SUSE publishes none, and some documents it lists are still in `index.txt` and served — the index wins.

Removal runs only when the sync can vouch for what it emitted. A Sync error, a failed batch write, or a run cut short by `-limit` removes nothing; a whole-file feed that found its file unchanged ("up to date, skipping GET") emitted nothing, so it is not complete and removes nothing either. A CSAF run in which some documents failed is not complete, but still replaces the documents it did read and still withdraws. Ubuntu OpenVEX leaves documents out only when removal is enabled. Its stored fingerprints are cleared before a run changes any row — its first batch write, sweep or withdrawal — and a run's own are stored only once its replacement has succeeded, so a run that changed rows and did not replace them — removal disabled, failed or refused, a sync or batch-write error, a `-limit` cut, a killed process — leaves none, and the next run that fetches the tarball reads every document; a malformed document gets no fingerprint and stays live. A removal that fails or is refused is logged and never fails the adapter: the data was written, the watermark advances, and the next sync retries. Ubuntu OpenVEX's watermark is the exception: it is the tarball's `Last-Modified`, and it does not advance past a publish whose removal (or withdrawal) did not finish, so the next run fetches that tarball again rather than finding it up to date — which is also what lets a `-sweep-force` run act on it.

A sweep counts before it deletes: one pass over the adapter's rows in scope counts them and records the `ctid` of each unseen one in a temp table (about 36 bytes per gone row), so a refused sweep writes nothing to `statements`. Only then are the recorded rows deleted, in batches of at most five million, so no single statement's array of `ctid`s nears Postgres' limit. All of it is one `REPEATABLE READ` transaction: every batch sees the snapshot the gone set was found in, and a row changed concurrently fails the sweep rather than being deleted on stale evidence. Each statement of a sweep or withdrawal is bounded at two hours server-side (the longest, a whole-feed sweep's anti join, took 85 minutes on the full Ubuntu feed), and a whole call at six.

**`-sweep-max-fraction`** (default `0.2`, within `[0, 1]`) sets both fraction guards. `0` disables every removal mechanism and records no seen keys (rows still record their owner); `1` lifts the fraction guards, but a whole-feed sweep that saw nothing is still refused.

**A refused sweep is sticky.** The rows it would have deleted stay, and the next run counts them in its denominator again, so the sweep stays refused until the guard is lifted. `-sweep-force <adapter-id>[,…]` lifts both fraction guards, for the named adapters only, on every ingest the process runs; an id no configured adapter has refuses to start, so a typo cannot leave the guard silently in place. The nothing-seen and empty-manifest refusals stay, and `-sweep-max-fraction 0` still disables removal. A forced whole-feed sweep and a forced withdrawal log `forced=true`. Run one ingest with it, then remove it.

**A changed verdict.** The verdict (status and justification) is part of a row's key, so a verdict the vendor changed is written as a new row, and the old row goes only when removal deletes it. With removal disabled, or while the adapter's sweep is refused, the old verdict is served beside the new one.

**Log lines.** An adapter run that reaches its sync logs exactly one `sweep` line; a run that fails before it — at discovery, recording its vendor, or reading its watermark — logs none. A CSAF run also logs one `withdraw` line when it trusted its `index.txt` and its removal was not skipped:

```
INFO sweep adapter=ubuntu-vex scope=all seen=195636880 owned=195702113 deleted=65233
INFO sweep adapter=redhat scope=cves:412 seen=38117 owned=40269 deleted=2152
INFO sweep adapter=debian-oval-bookworm scope=cves:0 seen=0 owned=0 deleted=0 skipped=incomplete
WARN sweep adapter=alpine-secdb-v3.21-main scope=all seen=5120 owned=7012 deleted=0 refused="would delete 1892 of 7012 owned rows (26.98%), over the 20.00% limit"
INFO withdraw adapter=redhat live=69854 held_cves=69864 withdrawn_cves=10 deleted=963
```

`scope` is `all` for a whole-feed sweep and `cves:<n>` for the CVEs a CSAF or Ubuntu OpenVEX run refreshed; `seen` counts keys emitted (duplicates included), `owned` the adapter's rows within scope. `skipped=incomplete` is the normal line for a feed that had not changed; the other `skipped` values are `disabled`, `sync error`, `flush error`, `limit`, `start error` and `aborted`. A refusal is a WARN with `deleted=0` and the reason; a failure is an ERROR with the error. The values above are illustrative.

**Disk.** Measured on the full Ubuntu OpenVEX feed (~196M owned rows), a whole-feed sweep took 85 minutes and ~84-116 GB of transient disk above the database's steady size: the seen table, the hash-join temp files, the adapter's materialised owned rows, and the gone set's temp table at about 36 bytes per gone row. All of it is released when the sweep ends. The sweep sets `temp_file_limit = '100GB'` only when its role is a superuser; a managed database's role cannot set it, so there the spill is bounded only by free disk. Deleted rows also write WAL (about one full page image each; `docker-compose.yml` sets `wal_compression=lz4`), and `statements` is autovacuumed at 1% of the table plus 100,000 rows so the freed space is reused after each sweep.

### Scheduling

The `serve` command runs ingest automatically on a configurable interval (default 24h). On boot it ingests at once unless the newest `adapter_state` write is within the interval, in which case the first run waits for the rest of it (`boot ingest skipped`); `-no-scheduler` turns the scheduler off. On-demand ingest is available via `POST /v1/ingest` (requires admin token). Every one of these takes the ingest lock, so they never overlap.

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
      boundary.go              -- the version kind of a fixed-in statement
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
      store.go, types.go, boundary.go (fixed-in version comparison)
      postgres/                -- PostgreSQL backend (jackc/pgx): migrations.go, postgres.go, sweep.go
      dbtest/                  -- in-memory fake Store for tests
    api/                       -- HTTP handlers
      handler.go, analyze.go, arch.go, gzip.go, ingest.go, request_log.go
  test/integration/api_test.go -- end-to-end tests (binary + DB + HTTP)
  test/acceptance/             -- acceptance suite: trimmed vendor feeds → ingest → exact HTTP answers
  testdata/                    -- fixtures: CSAF slices, per-feed OVAL and secdb samples, alias sample
  config.yaml                  -- adapter + alias-fetcher configuration
  Dockerfile                   -- golang:1.27-alpine → alpine:3.24
```

**Companion library**: [`getreeldev/oval-to-vex`](https://github.com/getreeldev/oval-to-vex) — standalone Go library that parses Ubuntu, Debian, AlmaLinux, and Oracle Linux OVAL XML into VEX-shaped statements. Zero dependencies beyond stdlib. reel-vex's four OVAL adapters delegate to it; anyone else building scanners can `go get github.com/getreeldev/oval-to-vex/translator`.
