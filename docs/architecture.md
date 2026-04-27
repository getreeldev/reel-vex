# reel-vex architecture

Deep-dive companion to the [README](../README.md). Covers the ingest pipeline, source-adapter framework, alias fetcher framework, sync strategy, scheduling, and the on-disk project layout. For the API, see [`api.md`](./api.md). For the database schema, see [`data-model.md`](./data-model.md).

## Ingest pipeline

The pipeline is driven by `config.yaml`: a list of adapters (VEX feeds) and alias fetchers (identifier mapping files). Each adapter implements the same `source.Adapter` interface — `Discover`, then `Sync` — so the orchestrator (`pkg/ingest/ingest.go`) is format-agnostic.

### CSAF adapter

Each CSAF provider publishes a `provider-metadata.json` at a well-known URL. The adapter fetches it, finds the VEX distribution URL, reads `changes.csv`, and enumerates documents since the last-synced watermark.

Parsing uses [`gocsaf/csaf`](https://github.com/gocsaf/csaf) (the strict path) with a permissive map-based fallback for vendor feeds that violate CSAF 2.0 schema rules (SUSE's CPE 2.3 deviations, for example). Extracted per document:

- **Product IDs** from `product_tree.branches` (recursive walk) and `product_tree.relationships` (composite products). Both PURL and CPE identifiers, inherited from both sides of each relationship so platform CPEs end up on composite products.
- **CVE statuses** from `vulnerabilities[].product_status`: `not_affected`, `fixed`, `affected`, `under_investigation`.
- **Justifications** for `not_affected`: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`.

### OVAL adapters

Three OVAL adapters share the same fetch/parse flow: Red Hat, Ubuntu, and Debian. Each adapter instance fetches a single bz2-compressed OVAL XML file (one config entry per file/release). A `HEAD` check against `Last-Modified` short-circuits the GET when upstream hasn't regenerated the file. On a pull, the response is streamed through `compress/bzip2` and parsed via [`getreeldev/oval-to-vex`](https://github.com/getreeldev/oval-to-vex) — a dedicated OVAL-to-VEX translator library maintained alongside reel-vex, with per-vendor parsers (`FromRedHatOVAL`, `FromUbuntuOVAL`, `FromDebianOVAL`).

The Red Hat OVAL adapter exists to fill the coverage gap that Red Hat's CSAF feed intentionally leaves: EUS / AUS / E4S / SAP / HA / NFV stream-suffix CPEs (see [SECDATA-1181](https://redhat.atlassian.net/browse/SECDATA-1181)). OVAL has them; CSAF doesn't. Ubuntu and Debian don't publish CSAF, so OVAL is the primary feed for those vendors. Ubuntu deb-shaped statements emit `pkg:deb/ubuntu/<name>?distro=ubuntu-<version>` PURLs; Debian emits `pkg:deb/debian/<name>?distro=debian-<N>`. The `distro` qualifier is part of identity — focal `openssl` and noble `openssl` are distinct products with different fix versions.

### Alias fetchers

Independent from VEX adapters. Each fetcher pulls a vendor-published mapping file and writes rows into `product_aliases`. The first implementation is Red Hat's `repository-to-cpe.json` — lets a scanner querying with a PURL carrying `?repository_id=rhel-8-for-x86_64-appstream-rpms` match VEX statements keyed on `cpe:/a:redhat:enterprise_linux:8::appstream`.

### Sync strategy

- **First run**: adapters pull their entire feed. CSAF for Red Hat is ~313K per-CVE documents and takes hours; SUSE is ~54K. OVAL is one bz2 file per adapter, seconds to minutes.
- **Incremental**: every adapter stores its own watermark in `adapter_state.last_synced`. CSAF adapters skip documents older than their watermark; OVAL adapters HEAD the feed and skip the GET when unchanged.
- **Batch writes**: statements accumulate in memory and flush to SQLite in batches of 5,000.

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
      csafadapter/             -- CSAF adapter (wraps pkg/csaf)
      redhatoval/              -- Red Hat OVAL adapter (wraps oval-to-vex)
      ubuntuoval/              -- Ubuntu OVAL adapter (wraps oval-to-vex)
      debianoval/              -- Debian OVAL adapter (wraps oval-to-vex)
    aliases/                   -- alias-fetcher framework
      aliases.go               -- Fetcher interface + registry
      redhat.go                -- Red Hat repository-to-cpe.json fetcher
    resolver/                  -- query-time identifier expansion
      cpe.go                   -- CPE 2.2 5-part prefix
      resolver.go              -- direct / via_alias / via_cpe_prefix
    ingest/ingest.go           -- orchestrator (adapters → statements; fetchers → aliases)
    db/                        -- SQLite + schema migrations
      db.go, migrations.go
    api/                       -- HTTP handlers
      handler.go, sbom.go, ingest.go
  test/integration/api_test.go -- end-to-end tests (binary + DB + HTTP)
  testdata/                    -- fixtures: CSAF slices, OVAL fixture, alias sample
  config.yaml                  -- adapter + alias-fetcher configuration
  Dockerfile                   -- golang:1.26-alpine → alpine:3.21
```

**Companion library**: [`getreeldev/oval-to-vex`](https://github.com/getreeldev/oval-to-vex) — standalone Go library that parses Red Hat, Ubuntu, and Debian OVAL XML into VEX-shaped statements. Zero dependencies beyond stdlib. reel-vex's three OVAL adapters delegate to it; anyone else building scanners can `go get github.com/getreeldev/oval-to-vex/translator`.
