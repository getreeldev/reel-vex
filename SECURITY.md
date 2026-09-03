# Security policy

## Reporting a vulnerability

Email **security@getreel.dev** with enough detail to reproduce the issue. A short
proof of concept helps; please don't open a public issue for anything exploitable.

Alternatively, use **Report a vulnerability** under the Security tab of any of our
public repositories — that opens a private advisory thread with us on GitHub and
never depends on mail delivery.

You'll get an acknowledgement within 5 working days. Reel is a small project, so
please allow reasonable time for a fix before disclosing publicly — 90 days is a
good default, and we're happy to agree something shorter for a low-severity finding.

## Scope

Anything we publish: the `reel` CLI and agent, the Helm chart at
`oci://docker.io/getreel/helm`, the `getreel/*` container images, the GitHub Action,
and the VEX service at `vex.getreel.dev`.

Out of scope: reports from automated scanners with no demonstrated impact, missing
security headers on marketing pages, and anything requiring a compromised host or
cluster-admin access you already hold.

## No bug bounty

We don't run a paid bounty programme and can't offer rewards. We will credit you in
the release notes for the fix if you'd like to be named.

## Please don't

If a credential ever turns up in something we published, tell us — but don't use it.
Accessing our systems or private repositories with a found credential goes beyond
research, and we'd rather hear about the leak than learn its blast radius the hard way.
