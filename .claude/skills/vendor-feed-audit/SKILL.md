---
name: vendor-feed-audit
description: Audit every public security data feed a vendor publishes — confirm we're consuming the broadest one in reel-vex and document any gaps. Use when adding a new adapter, when survivorship bias is suspected (we missed a better feed), or as a periodic re-survey. Findings go to a dated notes file outside this public repository.
---

# Vendor security-feed audit

Goal: for each vendor reel-vex consumes, enumerate **every** public security data feed they publish. Decide which to consume, which to skip, which to queue. Avoids the survivorship bias of "we wired up the first feed Google surfaced and assumed that was all there was."

Run this when:
- Adding a new adapter (audit the new vendor's full feed inventory before locking in a URL).
- A user reports gaps in coverage that a different feed from the same vendor might fill.
- Periodically (every ~6 months) for vendors we already consume — they ship new feeds.

Output:
- A dated audit report (`vex-feed-audit-<YYYY-MM-DD>.md`) kept **outside this repository** — it is public, and an audit is working notes, not documentation. Ask the maintainer where it goes.
- One paragraph in chat per "queued" feed explaining the call

## Methodology

### 0. Scope review — what vendors *should* we cover?

Before probing the vendors we already consume, validate the **vendor list itself** against a target coverage matrix. Two axes:

- **Major Linux distros** — RHEL family (RH, Oracle, AlmaLinux, Rocky), Debian family (Debian, Ubuntu), SUSE family (SLES, openSUSE), Amazon Linux (AL2, AL2023), Microsoft (Azure Linux / CBL-Mariner), VMware Photon OS, Arch (rolling — usually skip for VEX), Gentoo (skip).
- **Container base ecosystems** — Alpine, Wolfi (Chainguard), distroless (Google — borrows from Debian), UBI (RH), `chainguard/static`. These dominate scanner queries.

For each row, ask: do we have any rows in `vendors` for it today? If no, that's a **scope gap** — record it and run the per-vendor probes against it (Phase 2 onward) regardless of whether it was on the original config.yaml.

This step exists because the original 2026-04-30 audit scoped to vendors-we-already-consume and missed Amazon Linux + Alpine + Wolfi entirely. Don't repeat that.

### 1. Inventory what we consume today

Read `config.yaml`. For each entry under `adapters:` and `aliases:`, record:
- vendor, format, URL, identifier scheme (PURL / CPE / repo-id), alias dependencies.

Then merge with the Phase 0 scope-gap list to produce the full set of vendors to probe.

### 2. Hypothesise siblings on the same host

Take the URL we consume. Walk up to its parent directory and `curl` it — most vendors expose Apache-style `Index of` listings.

```bash
curl -sS "https://<host>/<parent-dir>/" | grep -oE 'href="[^"]+"' | head -40
```

Try common format names alongside what we consume:

```
/csaf/  /csaf-vex/  /csaf-advisory/
/cvrf/  /cvrf-cve/   (legacy CSAF predecessors)
/oval/  /oval-affected/  /oval-patch/
/openvex/  /vex/
/security-data/  /metrics/  /aliases/
```

For each candidate directory, also try: `index.json`, `index.txt`, `changes.csv`, `provider-metadata.json`.

### 3. Hypothesise on alternate hosts

A vendor often publishes the same data through more than one channel. Probe:

- **Primary site**: `vendor.com/security/...`, `vendor.com/security/cves.json`
- **API subdomains**: `api.vendor.com`, `securitydata.vendor.com`, `security-tracker.vendor.com`, `security-metadata.vendor.com`
- **Per-CVE REST**: `vendor.com/security/cves/CVE-X.json`, `vendor.com/api/cve/CVE-X`
- **Hydra-style query API**: `vendor.com/hydra/rest/securitydata/cve.json?after=<date>`
- **Well-known paths**: `vendor.com/.well-known/csaf/provider-metadata.json`
- **Source-of-truth GitHub repos**: `github.com/<vendor>/security-*`, `<vendor>/cve-*`, `<vendor>-security-notices`. Check both repo HTML and `raw.githubusercontent.com/.../<file>`.
- **GitLab/Salsa**: `salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list`
- **Mirror archives**: `ftp.<vendor>.com/pub/projects/security/`

### 4. Probe in parallel

Batch HEADs in one bash block — one row per URL with HTTP status. Codes:

- `200` → exists; characterize.
- `404` → no.
- `405` → exists but rejects HEAD (REST APIs that only accept GET — re-probe with GET).
- `301`/`302` → follow `-L`.
- `403` → may exist behind auth/region — note and move on unless it's critical.

```bash
for url in \
  "..." \
  "..."; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -I "$url")
  echo "$code  $url"
done
```

### 5. Characterize each confirmed feed

For each `200`, record:

| Field | Examples |
|---|---|
| Format | CSAF 2.0 / OpenVEX 0.2.0 / OVAL / CVRF / vendor REST / vendor JSON dump |
| Coverage scope | All triaged CVEs / fixed only / per-USN / per-DSA / per-package |
| Identifier scheme | PURL / CPE / repository-id / package-name + release |
| Incremental mechanism | `Last-Modified` (HEAD-skip) / `changes.csv` (per-doc delta) / `?after=<date>` query / `ETag` per file / git SHA |
| Cadence | real-time / daily / on-USN / on-DSA |
| License + attribution | check the index page; OVAL is usually CC-BY, CSAF varies |

For sample feeds, GET one document and confirm the schema matches expectations:

```bash
curl -sS "<feed>" | python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d.keys())[:10])"
```

### 6. Decide each feed's role

For every confirmed feed, label it:

- **strict-superset** → replace what we have
- **complementary** → add alongside (different coverage shape — e.g. CSAF triage + OVAL fixed)
- **redundant** → skip (legacy format with same data as a newer one we already consume)
- **future** → record but defer (low-value or significant adapter cost)

The decision rule is in this repository's `CLAUDE.md` under "Where a per-source fix lives" — if a feed fills a coverage gap only it can fill, it earns an adapter.

### 7. Produce the audit report

Per-vendor table with columns: feed | format | coverage | identifier | incremental | status (consume / skip / queued).

For every "queued" feed, one paragraph in chat: what gap it fills, what would change in `config.yaml` + `pkg/source/`, and rough effort.

Write the report to the dated file named under *Output* above, never into this repository.

## Vendor cheatsheet (known patterns)

Update this list as new vendors are audited.

### Red Hat
- `security.access.redhat.com/data/csaf/v2/vex/` (CSAF VEX, per-CVE)
- `security.access.redhat.com/data/csaf/v2/` (CSAF advisories per RHSA)
- `security.access.redhat.com/data/oval/v2/` (OVAL, per-RHEL stream incl. EUS/AUS/E4S)
- `security.access.redhat.com/data/metrics/repository-to-cpe.json` (alias)
- `security.access.redhat.com/data/metrics/container-name-repos-map.json` (alias — container image → repo IDs)
- `access.redhat.com/hydra/rest/securitydata/cve/<id>.json` (REST per-CVE; supports `?after=<date>` listing)

### SUSE
- `ftp.suse.com/pub/projects/security/csaf-vex/` (CSAF VEX, per-CVE)
- `ftp.suse.com/pub/projects/security/csaf/` (CSAF advisories per SUSE-SU)
- `ftp.suse.com/pub/projects/security/cvrf-cve/` (legacy per-CVE, redundant w/ csaf-vex)
- `ftp.suse.com/pub/projects/security/cvrf/` (legacy per-advisory, redundant w/ csaf)
- `ftp.suse.com/pub/projects/security/oval/` (OVAL, per-product `.xml`/`.xml.gz`; SLES, openSUSE Leap, Tumbleweed; -patch / -affected variants)
- `www.suse.com/.well-known/csaf/provider-metadata.json` (CSAF discovery)

### Canonical / Ubuntu
- `security-metadata.canonical.com/oval/com.ubuntu.<release>.usn.oval.xml.bz2` (USN-derived OVAL — fixed-only)
- `security-metadata.canonical.com/vex/vex-all.tar.xz` (OpenVEX 0.2.0, per-CVE files in tar; **strict superset** of OVAL coverage incl. pre-USN triage)
- `ubuntu.com/security/cves.json` (paginated REST)
- `ubuntu.com/security/cves/<id>.json` (per-CVE REST)
- `ubuntu.com/security/notices.json` (USN listing)
- GitHub mirror: `github.com/canonical/ubuntu-security-notices` (raw.githubusercontent.com works for per-file `ETag` access)

### Debian
- `www.debian.org/security/oval/oval-definitions-<release>.xml.bz2` (OVAL — DSA-derived, fixed-only)
- `security-tracker.debian.org/tracker/data/json` (full security-tracker JSON dump — complementary, includes pre-DSA triage state per release)
- `salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list` (the human-edited source-of-truth CVE list)
- `www.debian.org/security/dsa.rdf`, `dsa-long.rdf` (DSA listings, not VEX)

### Amazon Linux
- `explore.alas.aws.amazon.com/CVE-<id>.json` (per-CVE vendor JSON; `status`: `PendingFix` / `Fixed` / `NotApplicable`; `affected_packages[].platform` = `amzn2` / `amzn2023`; `opt_in_repo` for kernel variants)
- `alas.aws.amazon.com/AL2/alas.rss`, `AL2023/alas.rss` (RSS advisory listings — useful as a cheap change feed; per-CVE detail still needs the JSON URL)
- Note: directory listings (`AL2/`, `AL2023/`) return 403 — Amazon doesn't expose Apache `Index of`. Backfill needs an external CVE list as the iteration driver.

### Alpine Linux
- `secdb.alpinelinux.org/v<release>/main.json`, `community.json` (per-release × repo; `secfixes` map fixed-version → CVEs)
- `secdb.alpinelinux.org/` (parent index — lists all releases)
- Standard Alpine secdb format; same shape as Wolfi.

### Wolfi (Chainguard)
- `packages.wolfi.dev/os/security.json` (single file, all packages × per-version `secfixes`)
- Alpine-format secdb.

### Oracle Linux
- `linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2` (everything)
- `linux.oracle.com/security/oval/com.oracle.elsa-<year>.xml.bz2` (per-year slices; cheaper incremental)
- Standard OVAL XML.

### AlmaLinux
- `errata.almalinux.org/<major>/errata.full.json` (per-major-version, e.g. `8`, `9`, `10`)
- Vendor JSON; per-erratum `severity`, `packages`, `references`.

### Rocky Linux
- `errata.rockylinux.org/api/v2/advisories` (REST, paginated)
- Per-advisory: `name`, `severity`, `affectedProducts`, `fixes`.

### Azure Linux / CBL-Mariner (Microsoft)
- `raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/azurelinux-3.0-oval.xml`
- `raw.githubusercontent.com/microsoft/AzureLinuxVulnerabilityData/main/cbl-mariner-2.0-oval.xml`
- GitHub-hosted, one OVAL XML per release.

### VMware Photon OS
- `packages.vmware.com/photon/photon_oval_definitions/` (parent dir; needs a deeper probe — listing format isn't standard Apache `Index of`).

## Notes

- **OVAL ≠ VEX.** OVAL is a *fixed-state* feed: it tells you what shipped a fix in which package version. VEX (CSAF, OpenVEX) covers triage state too: `not_affected`, `under_investigation`, etc. Most vendors publish both — if we only consume their OVAL, we miss everything still in triage. This was the Ubuntu-OVAL-vs-Ubuntu-VEX mistake on 2026-04-30.
- **Don't trust search engines for feed enumeration.** Vendor docs link to one feed; the others sit under sibling directories. Walk the directory listings.
- **Apache `Index of` listings** are the highest-yield surface. If a vendor exposes one, scrape the `href=` lines — that's their full inventory.
- **CSAF 2.0 has `provider-metadata.json` as a discovery file.** If a vendor publishes CSAF, that file points at `distributions[].rolie.url` for the change feed — same machine-readable discovery applies for any new CSAF vendor we add.
