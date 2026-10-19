# Acceptance fixtures

Trimmed copies of the live vendor feeds, served to the adapters by the acceptance suite. Fetched on **2026-10-03** from the URLs in `config.yaml` (and the CSAF
provider-metadata → distribution → `changes.csv`/`index.txt` chain), except the Canonical
OpenVEX tarball, copied on **2026-10-02**.

**Trimming rule.** Items were only dropped whole (tar entries, OVAL definitions and the tests,
objects, states and variables only dropped definitions used, secdb packages, updateinfo `<update>`s, CSAF
documents, index lines, `repomd.xml` `<data>` entries, alias-file repositories). No vendor
statement in a kept item was edited. Trimmed JSON files are re-serialised (whitespace only), and
the [day-2 files](#day-2-second-ingest) are edited on purpose.

## Licences

`testdata/feeds` and `testdata/src` are vendor data under each vendor's terms, **not** the
repository's Apache-2.0 licence.

| Feed | Terms | Attribution |
|---|---|---|
| Red Hat CSAF VEX, `repository-to-cpe.json` | CC BY 4.0 (each document's `legal_disclaimer`) | © Red Hat, Inc. |
| SUSE CSAF VEX | CC BY 4.0 (each document's `legal_disclaimer`) | © SUSE LLC |
| SUSE Rancher VEX hub | CC BY 4.0 (the repository's `LICENSE`) | © SUSE LLC / Rancher |
| Canonical OpenVEX | CC BY-SA 4.0, as `canonical/ubuntu-security-notices` | © Canonical Ltd. |
| Ubuntu OVAL | Canonical's terms (`<rights>` kept) | © Canonical Ltd. |
| Debian OVAL | Debian's terms | Debian |
| Alpine secdb | CC BY-SA 4.0 | Alpine Linux |
| Amazon Linux ALAS `updateinfo` | Amazon's terms | © Amazon.com, Inc. or its affiliates |
| AlmaLinux OVAL | MIT, as `AlmaLinux/osv-database` (copyright kept) | © AlmaLinux OS |
| Oracle Linux OVAL | Oracle's terms (copyright kept) | © Oracle and/or its affiliates |

The CC BY-SA fixtures are adaptations, shared under CC BY-SA 4.0. Licences:
https://creativecommons.org/licenses/by/4.0/, https://creativecommons.org/licenses/by-sa/4.0/.

## Layout

- `feeds/day1/<host>/<path>` is served at `/<host>/<path>`. The server rewrites `https://` in
  `provider-metadata.json` and `mirror.list` to itself; the files on disk are verbatim.
- `feeds/day2/…` replaces its day-1 copy on day 2.
- `src/day1/…`, `src/day2/…` hold the content of every compressed file. After editing `src/`,
  rebuild with `cd test/acceptance/testdata && go run gen.go` (needs `bzip2`;
  reproducible output). `TestFixturesMatchSource` (no database, no build tag) fails when a
  compressed file differs from `src/`.

**What the server checks.** Each ingest must ask for every file of its day. Any 404 fails it,
except SUSE's `archive_latest.txt` on day 1 and the document gone on day 2.

**Last-Modified.** Day-1 files are served as `Sat, 03 Oct 2026 00:00:00 GMT`, day-2 replacements
as `Sun, 04 Oct 2026 00:00:00 GMT` (one is pinned, below). OVAL and secdb rows carry the day-1
date (`2026-10-03T00:00:00Z`). Dates below are the vendor's Last-Modified.

## Feeds

### Red Hat CSAF VEX — `security.access.redhat.com/data/csaf/v2/`

- `provider-metadata.json` and `vex/archive_latest.txt` (`csaf_vex_2026-09-27.tar.zst`), verbatim.
- `vex/changes.csv`, `vex/index.txt` (2026-10-03): the seven documents' lines, in vendor order.
- `vex/<year>/cve-*.json`, verbatim (*archive*: only in the bulk archive on day 1):
  `2023/cve-2023-34034.json`, `2025/cve-2025-20012.json`, `2025/cve-2025-6270.json` (*archive*),
  `2026/cve-2026-47699.json` (*archive*), `2026/cve-2026-88265.json`, `2026/cve-2026-94282.json`,
  `2026/cve-2026-101295.json`.
- `vex/csaf_vex_2026-09-27.tar.zst` is **built here** from `src/day1/redhat-archive/` (the two
  *archive* documents), in the vendor's format: a zstd tar of `<year>/cve-<id>.json` without
  directory entries, checked against the real archive's first 400 KB. Day 1 must log
  `csaf bulk archive: done … docs=2`.
- `../metrics/repository-to-cpe.json`: `last_updated` and five repositories,
  `public-hummingbird-x86_64-rpms`, `rhel-10-for-x86_64-baseos-rpms`,
  `rhel-8-for-x86_64-appstream-rpms`, `rhel-8-for-x86_64-baseos-rpms`,
  `rhel-9-for-x86_64-baseos-eus-rpms`.

### SUSE CSAF VEX — `www.suse.com/.well-known/csaf/provider-metadata.json`, `ftp.suse.com/pub/projects/security/csaf-vex/`

- `provider-metadata.json`, verbatim. No `archive_latest.txt` (404, as live): a cold start crawls
  `changes.csv`.
- `changes.csv`, `index.txt`: the four documents' lines.
- Verbatim: `cve-2025-1914.json`, `cve-2017-15535.json`, `cve-2025-26791.json`, and
  `cve-2025-22077.json` (kept for `first_fixed`).

### Canonical OpenVEX — `security-metadata.canonical.com/vex/vex-all.tar.xz`

Source: https://security-metadata.canonical.com/vex/vex-all.tar.xz, copied 2026-10-02. Kept
(`src/day1/ubuntu-vex/`), verbatim, in a tar with directory entries like the vendor's:

`vex/cve/2016/CVE-2016-9571.json`, `vex/cve/2018/CVE-2018-20543.json`,
`vex/cve/2022/CVE-2022-2060.json`, `vex/cve/2022/CVE-2022-33972.json`,
`vex/cve/2022/CVE-2022-37434.json`, `vex/cve/2026/CVE-2026-41990.json`, `vex/cve/2022/CVE-2022-21180.json`, and `vex/usn/USN-7560-1.json`, which the
adapter must not read.

### Ubuntu OVAL — `security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2`

Source: https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2
(2026-10-02). Kept: `oval:com.ubuntu.noble:def:673620000000` (USN-6736-2 klibc),
`…:def:666330000000` (USN-6663-3, no CVE), `…:def:675610000000` (USN-6756-1 less),
`…:def:674430000000` (USN-6744-3 Pillow), and the inventory definition they extend.

### Debian OVAL — `www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2`

Source: https://www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2 (2026-10-03).
Kept (`oval:org.debian:def:`):
`308370225544215691963860905694509241784` (CVE-2016-5416 389-ds-base, evr `0:0`),
`71475824035904533640313774911074609996` (CVE-2001-1534 apache2, `0:0`),
`118596735315433746990801407057633161948` (CVE-2022-37434 zlib),
`54799239821264313931010316258924094420` (CVE-2022-37434 libz-mingw-w64),
`61325699286411249562200157530598017542` (DSA-5439-1 bind9),
`166558133375782793613486575811727984470` (CVE-1999-1332 gzip),
`302398480618719661759273474285073383836` (CVE-1999-0199 glibc).

### SUSE Rancher VEX hub — `github.com/rancher/vexhub/archive/refs/heads/main.tar.gz`

Source: https://github.com/rancher/vexhub/archive/refs/heads/main.tar.gz at commit
`14ccc8f1ff2cadd0c12f351244f801cbb1e9801d` (in the tar's pax global header comment). Kept under
`vexhub-main/`: `vex-repository.json` (verbatim), `index.json` (trimmed to six packages), and these
per-package directories, verbatim:

- `pkg/golang/github.com/open-policy-agent/opa/`
- `pkg/golang/github.com/projectcalico/calico/lib/std/`
- `pkg/oci/index.docker.io/kubeovn/kube-ovn/`
- `pkg/oci/index.docker.io/rancher/mirrored-messagebird-sachet/`
- `pkg/oci/registry.suse.com/rancher/mirrored-messagebird-sachet/` (the same zlib verdict, second scope)
- `pkg/oci/index.docker.io/rancher/nginx-ingress-controller/` (only SUSE-SU/FU statements and
  `[ERROR] CVE type  not mapped` subcomponents: emits nothing)

### Alpine secdb — `secdb.alpinelinux.org/v3.22/{main,community}.json`

Sources: https://secdb.alpinelinux.org/v3.22/main.json (2026-10-03) and
https://secdb.alpinelinux.org/v3.22/community.json (2026-09-11), top-level keys kept. Main: jansson, socat, libspf2, libdwarf, bubblewrap, cifs-utils, postgresql17 (CVE-2026-14681 under both `"0"` and `17.11-r0`). Community: git-lfs, hermes, netdata, opendkim.

### Amazon Linux ALAS — `cdn.amazonlinux.com/`

- `2/core/latest/x86_64/mirror.list`, `al2023/core/mirrors/latest/x86_64/mirror.list`: verbatim,
  each naming one mirror base.
- `<base>repodata/repomd.xml`: only the `updateinfo` `<data>` entry (stale checksums, which the
  adapter does not read).
- `<base>repodata/updateinfo.xml.gz`, from `src/day1/amazon/`: amzn2 keeps `ALAS2-2018-996` (no
  CVE), `ALAS2-2022-1844`, `ALAS2-2023-1957`; al2023 keeps `ALAS2023-2023-061`,
  `ALAS2023-2023-082`.

### AlmaLinux OVAL — `security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2`

Source: https://security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2 (2026-10-02). Kept:
`oval:org.almalinux.alsa:def:20225527` (squid), `…:def:20225716` (grafana).

### Oracle Linux OVAL — `linux.oracle.com/security/oval/com.oracle.elsa-ol{8,9}.xml.bz2`

Sources: https://linux.oracle.com/security/oval/com.oracle.elsa-ol9.xml.bz2 and …-ol8.xml.bz2
(2026-10-02). Both keep `oval:com.oracle.elsa:def:20240811` (ELSA-2024-0811, sudo) with its
release gates. The ol9 file also keeps `oval:com.oracle.elsa:def:20263516` (ELSA-2026-3516,
thunderbird, 38 CVEs), sized so the day-2 drop stays under the 20% sweep guard.

## Day 2 (second ingest)

**The only edits to vendor items**, each served with the day-2 Last-Modified unless marked:

| file | edit |
|---|---|
| `src/day2/ubuntu-vex/vex/cve/2016/CVE-2016-9571.json` | `statements[1]` (not_affected, esm-apps/xenial) removed |
| `src/day2/ubuntu-vex/vex/cve/2022/CVE-2022-2060.json` | `statements[0].status` under_investigation → affected |
| `feeds/day2/secdb.alpinelinux.org/v3.22/main.json` | cifs-utils `6.15-r0` loses CVE-2022-29869 |
| `feeds/day2/secdb.alpinelinux.org/v3.22/community.json` | hermes and netdata removed (4 of 8 rows: the guard case) |
| `src/day2/oval/oval-definitions-bookworm.xml` | gzip definition (CVE-1999-1332) removed |
| `src/day2/oval/com.ubuntu.noble.usn.oval.xml` | less definition (USN-6756-1) removed, but **served with the day-1 Last-Modified**, so the ingest must remove nothing |
| `src/day2/rancher/vexhub-main/index.json` + `gen.go` | kube-ovn (index.docker.io) package and directory removed |
| `feeds/day2/…/vex/2023/cve-2023-34034.json` | `red_hat_single_sign-on_7:spring-security` removed from known_not_affected and the flag |
| `feeds/day2/…/vex/2026/cve-2026-47699.json` | `product_status` and `flags` removed: re-published with zero statements |
| `feeds/day2/…/vex/changes.csv` | two new first lines: `"2023/cve-2023-34034.json","2026-10-04T06:00:00+00:00"` and `"2026/cve-2026-47699.json","2026-10-04T05:00:00+00:00"` |
| `feeds/day2/…/vex/index.txt` | `2026/cve-2026-94282.json` removed, and the document 404s |
| `feeds/day2/ftp.suse.com/…/csaf-vex/index.txt` | `cve-2017-15535.json` removed (1 of 4 CVEs: the withdrawal guard case); `changes.csv` unchanged |
| `src/day2/oval/com.oracle.elsa-ol9.xml` | ELSA-2024-0811 removed (the ol8 file keeps it) |

## Dates the cases expect

- CSAF: the `changes.csv` date, equal to `document.tracking.current_release_date` on day 1
  (archive documents included). Re-published day-2 documents keep their day-1 tracking dates.
- OpenVEX (Canonical, Rancher): the statement's timestamp, else the document's.
- updateinfo: the advisory's `<updated date>`.
- OVAL and secdb: the file's Last-Modified, although OVAL definitions carry their own dates.
  Using those instead is an open question.
