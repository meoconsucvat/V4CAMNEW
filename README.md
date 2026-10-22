# V4CAMNEW / VCAMPLUS

VCNext build 37 analysis, commercial packaging automation and username/password
licensing service source. The application bundle and package identity remain
`com.vcnext.app`; VCAMPLUS is the commercial display branding.

## Layout

| Directory | Purpose |
| --- | --- |
| `server/` | Service/admin source, systemd/Nginx templates and redacted environment example |
| `scripts/` | Build, patch, verification and camera diagnostic automation |
| `vcam/` | OBS/streaming documentation and feeder source |
| `docs/` | Architecture and dated audit reports |
| `dist/VCAMPLUS-roothide.deb` | Explicitly reviewed distributable snapshot |

## Credentials and operational state

Private SSH/signing keys, real environment files, databases and their sidecars,
backups, extracted binaries, mock runtime state, analysis databases and release
ZIPs are excluded from Git. Ignore rules leave local files intact; they do not
protect already committed secrets or forced additions.

`server/vcnext.env.example` contains placeholders only. Provision the actual
environment, matching authority key and live database out of band. Do not replace
the deployed signing identity as an incidental source checkout/setup step.
The environment filename referenced by systemd is intentional; its contents are
not repository material.

## Before staging or committing

Run the local gate with Python 3.14+ and `cryptography` available:

```text
python -X utf8 scripts/audit_git_precommit.py
```

It evaluates real Git ignore behavior and scans selected bytes and nested
archives without contacting a service. After Git exists, it also checks index
blobs and reachable commit/tag history. It writes an explicit approved path list
and SHA-256 inventory under `docs/`. Read the audit report before publication.
Any changed/new content needs another scan. Never force-add ignored operational
files. The gate is a finite inspection, not a guarantee against arbitrary
obfuscated/encrypted secrets.

## Reproduction and deployment boundaries

Source publication is not deployment. No GitHub deployment workflow is included.
Remote repository Actions/webhooks/settings must be checked separately before a
push if they could deploy production.

Build/audit scripts reference local original packages, an `extracted/` tree,
fixture keys and a logo path. Those inputs are deliberately excluded; a clean
clone is not a self-contained native rebuild. Provision authorized inputs
separately rather than copying live keys or database snapshots into Git. Several
historical reports link to local raw evidence that is also excluded.

Server code uses `cryptography`; optional build/analysis tools additionally use
Pillow, Capstone, LIEF and Zstandard support. Consult the specific script and
dated deployment guide for its runtime requirements. Current package identity is
recorded in the staging manifest; earlier reports describe earlier hashes and
do not automatically certify a changed binary artifact.
