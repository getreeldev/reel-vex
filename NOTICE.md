# NOTICE — third-party data attribution

reel-vex aggregates and redistributes vendor-published security (VEX) data,
transformed into OpenVEX 0.2.0. It restates each vendor's statements (the
"mirror model") and does not assert its own vulnerability findings. Every served
statement records its origin through the `vendor` and `source_format` fields and
the provenance carried in `status_notes`.

## Data sources and their licenses

- **Alpine Linux — secdb** (https://secdb.alpinelinux.org/).
  Licensed under the Creative Commons Attribution-ShareAlike 4.0 International
  License (**CC BY-SA 4.0**), https://creativecommons.org/licenses/by-sa/4.0/.
  reel-vex transforms the Alpine secdb JSON into OpenVEX statements — an
  adaptation — and redistributes those statements **under CC BY-SA 4.0**, with
  attribution to Alpine Linux and a link to the source. Changes were made: the
  per-branch `secfixes` fixed-version map is converted to per-(CVE, package)
  OpenVEX `fixed`/`affected` statements keyed as `pkg:apk/alpine/<name>`.

- **AlmaLinux — errata** (https://security.almalinux.org/). The machine-readable
  errata/OSV dataset (https://github.com/AlmaLinux/osv-database) is published
  under the **MIT License**.

- **Red Hat** (CSAF, OVAL), **SUSE / Rancher** (CSAF, OpenVEX),
  **Canonical / Ubuntu** (OpenVEX, OVAL), **Debian** (OVAL), **Amazon Linux**
  (ALAS `updateinfo`), and **Oracle Linux** (OVAL) data is redistributed as
  published by each vendor, under their respective terms. These feeds are
  factual security advisories (CVE ↔ fixed-version / affected-CPE mappings),
  mirrored with provenance — consistent with their established public
  redistribution by other scanners and tools.

This NOTICE is provided in good faith and is not legal advice.
