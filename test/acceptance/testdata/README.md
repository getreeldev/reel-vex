# Acceptance fixtures

Trimmed copies of the live vendor feeds, served by the acceptance suite's fixture
server so every adapter ingests real vendor data. Everything here was fetched on
**2026-10-03** from the URLs in `config.yaml` (and the CSAF
provider-metadata → distribution → `changes.csv`/`index.txt` chain), except the
Canonical OpenVEX tarball, a copy taken on **2026-10-02**.

**Trimming rule.** Items were only ever dropped whole — tar entries, OVAL definitions
(with the tests, objects, states and variables no kept definition references), secdb
packages, updateinfo `<update>`s, CSAF documents, `changes.csv`/`index.txt` lines,
`repomd.xml` `<data>` entries, alias-file repositories. No vendor statement inside a
kept item was edited, with two exceptions that are not vendor statements: JSON files
that were trimmed (secdb, Rancher `index.json`, `repository-to-cpe.json`) are
re-serialised (whitespace only), and the day-2 files listed at the end are edited on
purpose.

## Layout

- `feeds/day1/<host>/<path>` — what the fixture server serves, at `/<host>/<path>`,
  i.e. the vendor URL with `https://` replaced by the server's address. Files whose
  content names other vendor URLs (`provider-metadata.json`, `mirror.list`) are served
  with every `https://` rewritten to the fixture server; the files themselves are
  verbatim.
- `feeds/day2/...` — files that replace their day-1 copy for the second ingest.
- `src/day1/...`, `src/day2/...` — the uncompressed content of every compressed
  container. `feeds/**/*.{tar.xz,tar.gz,tar.zst,bz2,gz}` are built from it by
  `gen.go` (`cd test/acceptance/testdata && go run gen.go`; needs `bzip2` on PATH).
  Output is byte-for-byte reproducible; regenerate after editing anything under `src/`.

**Last-Modified.** The server dates every day-1 file `Sat, 03 Oct 2026 00:00:00 GMT`
and every day-2 replacement `Sun, 04 Oct 2026 00:00:00 GMT` (except one pinned file,
below). OVAL and secdb rows have no date of their own and carry it
(`2026-10-03T00:00:00Z`). The vendors' own Last-Modified values on the fetch day are
noted per feed for reference.

## Feeds

### Red Hat CSAF VEX — `security.access.redhat.com/data/csaf/v2/`

- `provider-metadata.json` — verbatim
  (https://security.access.redhat.com/data/csaf/v2/provider-metadata.json).
- `vex/archive_latest.txt` — verbatim (`csaf_vex_2026-09-27.tar.zst`).
- `vex/changes.csv`, `vex/index.txt` — the lines of the seven documents below, in the
  vendor's order (vendor files: 69,847 / 69,853 lines; Last-Modified 2026-10-03).
- `vex/<year>/cve-*.json` — seven documents, verbatim:
  - `2023/cve-2023-34034.json` (spring-security: fixed, known_affected,
    known_not_affected + flag; CPE-only products),
  - `2025/cve-2025-20012.json` (microcode_ctl: fixed across AUS/E4S/EUS/TUS/ELS streams
    with epoch qualifiers, known_affected on RHEL 6, known_not_affected on RHEL 10),
  - `2025/cve-2025-6270.json` (hdf5, known_affected) — archive,
  - `2026/cve-2026-47699.json` (trustee: known_not_affected on RHEL 10,
    under_investigation on RHEL 9) — archive,
  - `2026/cve-2026-88265.json` (crun: known_affected incl. the RHEL 8
    `container-tools:rhel8` module stream, fixed on Hardened Images/Hummingbird),
  - `2026/cve-2026-94282.json` (libXi, under_investigation),
  - `2026/cve-2026-101295.json` (three container images, under_investigation).
- `vex/csaf_vex_2026-09-27.tar.zst` — **built here**, not downloaded (the real archive
  is ~300 MB). Same format the adapter reads from the vendor: a zstd-compressed tar of
  `<year>/cve-<id>.json` entries with no directory entries (checked against the first
  400 KB of the real archive on 2026-10-03). It holds the two documents whose
  `changes.csv` date is before the archive date (`src/day1/redhat-archive/`); the five
  later ones reach the adapter through the `changes.csv` delta, as on the live feed.
- `../metrics/repository-to-cpe.json` — five of the 13,032 repositories kept
  (`public-hummingbird-x86_64-rpms`, `rhel-10-for-x86_64-baseos-rpms`,
  `rhel-8-for-x86_64-appstream-rpms`, `rhel-8-for-x86_64-baseos-rpms`,
  `rhel-9-for-x86_64-baseos-eus-rpms`), plus `last_updated`.

### SUSE CSAF VEX — `www.suse.com/.well-known/csaf/provider-metadata.json`, `ftp.suse.com/pub/projects/security/csaf-vex/`

- `provider-metadata.json` — verbatim. SUSE publishes no `archive_latest.txt` (404,
  as live), so a cold start crawls `changes.csv`.
- `changes.csv`, `index.txt` — the lines of the four documents below (vendor files:
  70,073 lines each).
- `cve-2025-1914.json` (chromium: `recommended` only — the audit's SUSE case),
  `cve-2017-15535.json` (mongodb: known_not_affected with no flag, recommended),
  `cve-2025-26791.json` (velociraptor known_affected, argocd-cli recommended),
  `cve-2025-22077.json` (kernel; the one document kept for `first_fixed`, which SUSE
  writes only in some large documents: 27 of a 1,168-document sample used it, none
  under 320 KB; this one is 372 KB) — verbatim.

### Canonical OpenVEX — `security-metadata.canonical.com/vex/vex-all.tar.xz`

Source tarball: the 2026-10-02 copy of https://security-metadata.canonical.com/vex/vex-all.tar.xz
(68,845 `vex/cve` documents). Kept entries (`src/day1/ubuntu-vex/`), verbatim:
`vex/cve/2016/CVE-2016-9571.json` (affected / not_affected at two versions of one
release, esm-apps), `vex/cve/2018/CVE-2018-20543.json` (component_not_present),
`vex/cve/2022/CVE-2022-2060.json` (under_investigation, esm-apps-legacy),
`vex/cve/2022/CVE-2022-33972.json` (intel-microcode fixed/affected across five
releases, esm-infra/esm-infra-legacy), `vex/cve/2022/CVE-2022-37434.json` (zlib/klibc/
rsync, every release, includes `distro=trusty/esm`), `vex/cve/2026/CVE-2026-41990.json`
(libgcrypt20, fips/fips-updates/fips-preview tracks), `vex/cve/2022/CVE-2022-21180.json`
(intel-microcode, listed on 18.04 at a different version than CVE-2022-33972 lists it),
and one USN entry,
`vex/usn/USN-7560-1.json`, which the adapter must not read. The tar is rebuilt with
directory entries, as the vendor's has.

### Ubuntu OVAL — `security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2`

Source: https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2
(Last-Modified 2026-10-02). Kept definitions: `oval:com.ubuntu.noble:def:673620000000`
(USN-6736-2 klibc, four CVEs), `…:def:666330000000` (USN-6663-3, no CVE),
`…:def:675610000000` (USN-6756-1 less), `…:def:674430000000` (USN-6744-3 Pillow), and
the inventory definition they extend.

### Debian OVAL — `www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2`

Source: https://www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2
(Last-Modified 2026-10-03). Kept definitions (`oval:org.debian:def:`):
`308370225544215691963860905694509241784` (CVE-2016-5416 389-ds-base, evr `0:0`),
`71475824035904533640313774911074609996` (CVE-2001-1534 apache2, `0:0`),
`118596735315433746990801407057633161948` (CVE-2022-37434 zlib),
`54799239821264313931010316258924094420` (CVE-2022-37434 libz-mingw-w64),
`61325699286411249562200157530598017542` (DSA-5439-1 bind9, two CVEs),
`166558133375782793613486575811727984470` (CVE-1999-1332 gzip),
`302398480618719661759273474285073383836` (CVE-1999-0199 glibc).

### SUSE Rancher VEX hub — `github.com/rancher/vexhub/archive/refs/heads/main.tar.gz`

Source: https://github.com/rancher/vexhub/archive/refs/heads/main.tar.gz, commit
`14ccc8f1ff2cadd0c12f351244f801cbb1e9801d` (kept as the pax global header comment).
Kept under `vexhub-main/`: `vex-repository.json` (verbatim), `index.json` (trimmed to
the six packages below of 1,251), and, verbatim, the per-package files
`pkg/golang/github.com/open-policy-agent/opa/`, `pkg/golang/github.com/projectcalico/calico/lib/std/`,
`pkg/oci/index.docker.io/kubeovn/kube-ovn/`, `pkg/oci/index.docker.io/rancher/mirrored-messagebird-sachet/`,
`pkg/oci/registry.suse.com/rancher/mirrored-messagebird-sachet/` (the same zlib
verdict under a second scope) and `pkg/oci/index.docker.io/rancher/nginx-ingress-controller/`
(84 SUSE-SU/FU statements and 5 with `[ERROR] CVE type  not mapped` subcomponents:
emits nothing).

### Alpine secdb — `secdb.alpinelinux.org/v3.22/{main,community}.json`

Sources: https://secdb.alpinelinux.org/v3.22/main.json (Last-Modified 2026-10-03),
https://secdb.alpinelinux.org/v3.22/community.json (2026-09-11). Top-level keys kept;
packages kept — main: jansson, socat, libspf2 (CVE-2021-20314 under two fixed
versions), libdwarf (DW* advisory ids), bubblewrap, cifs-utils, postgresql17
(CVE-2026-14681 under both `"0"` and `17.11-r0`); community: git-lfs, hermes, netdata,
opendkim.

### Amazon Linux ALAS — `cdn.amazonlinux.com/`

- `2/core/latest/x86_64/mirror.list`, `al2023/core/mirrors/latest/x86_64/mirror.list` —
  verbatim; each names one mirror base (the GUID paths below).
- `<base>repodata/repomd.xml` — the `updateinfo` `<data>` entry kept, the other
  `<data>` entries dropped (its checksums no longer match the trimmed file; the
  adapter does not read them).
- `<base>repodata/updateinfo.xml.gz` — from `src/day1/amazon/`: amzn2 keeps
  `ALAS2-2018-996` (no CVE reference), `ALAS2-2022-1844`, `ALAS2-2023-1957`; al2023 keeps
  `ALAS2023-2023-061`, `ALAS2023-2023-082`.

### AlmaLinux OVAL — `security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2`

Source: https://security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2 (2026-10-02).
Kept definitions: `oval:org.almalinux.alsa:def:20225527` (squid),
`oval:org.almalinux.alsa:def:20225716` (grafana).

### Oracle Linux OVAL — `linux.oracle.com/security/oval/com.oracle.elsa-ol{8,9}.xml.bz2`

Sources: https://linux.oracle.com/security/oval/com.oracle.elsa-ol9.xml.bz2 and
…-ol8.xml.bz2 (2026-10-02). Each keeps `oval:com.oracle.elsa:def:20240811`
(ELSA-2024-0811, sudo on OL8; sudo and sudo-python-plugin on OL9), with its release
gates; the ol9 file also keeps `oval:com.oracle.elsa:def:20263516` (ELSA-2026-3516,
thunderbird, OL9 only, 38 CVEs — sized so the day-2 drop below stays under the 20%
sweep guard).

## Day 2 (second ingest)

Served only once the suite's day-2 cases are no longer pending. **These are the only
edits to vendor items**:

| file | edit | Last-Modified |
|---|---|---|
| `src/day2/ubuntu-vex/vex/cve/2016/CVE-2016-9571.json` | `statements[1]` (not_affected, esm-apps/xenial) removed | day 2 |
| `src/day2/ubuntu-vex/vex/cve/2022/CVE-2022-2060.json` | `statements[0].status` under_investigation → affected | day 2 |
| `feeds/day2/secdb.alpinelinux.org/v3.22/main.json` | cifs-utils `6.15-r0` loses CVE-2022-29869 | day 2 |
| `feeds/day2/secdb.alpinelinux.org/v3.22/community.json` | packages hermes and netdata removed (4 of 8 rows: the guard case) | day 2 |
| `src/day2/oval/oval-definitions-bookworm.xml` | gzip definition (CVE-1999-1332) removed | day 2 |
| `src/day2/oval/com.ubuntu.noble.usn.oval.xml` | less definition (USN-6756-1) removed | **day 1, pinned**: an unchanged Last-Modified must remove nothing |
| `src/day2/rancher/vexhub-main/index.json` + `gen.go` | kube-ovn (index.docker.io) package and file removed | day 2 |
| `feeds/day2/…/vex/2023/cve-2023-34034.json` | `red_hat_single_sign-on_7:spring-security` removed from known_not_affected and the flag | day 2 |
| `feeds/day2/…/vex/2026/cve-2026-47699.json` | `product_status` and `flags` removed: re-published with zero statements | day 2 |
| `feeds/day2/…/vex/changes.csv` | two new first lines: `"2023/cve-2023-34034.json","2026-10-04T06:00:00+00:00"` and `"2026/cve-2026-47699.json","2026-10-04T05:00:00+00:00"` | day 2 |
| `feeds/day2/…/vex/index.txt` | `2026/cve-2026-94282.json` removed (and the document 404s on day 2) | day 2 |
| `feeds/day2/ftp.suse.com/…/csaf-vex/index.txt` | `cve-2017-15535.json` removed (1 of 4 CVEs: the withdrawal guard case); SUSE's `changes.csv` is unchanged | day 2 |
| `src/day2/oval/com.oracle.elsa-ol9.xml` | ELSA-2024-0811 removed (the ol8 file keeps it) | day 2 |

The re-published CSAF documents keep their day-1 `document.tracking` dates; the adapter
dates CSAF rows by `changes.csv`.

## Dates the cases expect

- CSAF: the document's own date (`document.tracking.current_release_date`, equal to its
  `changes.csv` date for every document here), including the two archive-seeded Red Hat
  documents.
- OpenVEX (Canonical, Rancher): the statement's timestamp, else the document's.
- updateinfo: the advisory's `<updated date>`.
- OVAL and secdb: the file's Last-Modified (the server's day-1 date). OVAL definitions
  carry dates of their own; dating OVAL rows by the file is the product's current design,
  an open decision in PLAN-VEX-SWEEP.md §6 Backlog ("Found by Phase 3a").
