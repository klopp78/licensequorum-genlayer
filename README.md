# LicenseQuorum for GenLayer

LicenseQuorum creates an append-only, source-bound consensus receipt for a proposed use of an open-source package. It is intended for teams that need an auditable decision before incorporating a dependency into a commercial product, redistribution workflow, or hosted service.

## What the contract checks

1. `assess_license_usage` accepts an exact package name, version, requested use, and two to five public source URLs.
2. It requires sources from at least two independent hosts, renders them independently, and stores SHA-256 snapshot commitments.
3. GenLayer validators return `allowed`, `restricted`, or `needs_review`, along with exact package/version match flags, identified license IDs, and a normalized obligations list.
4. The resulting `lic_*` record persists the source manifest, snapshot bundle hash, context hash, result, and immutable accepted-write commitment.

## Reviewer path

Deploy `contracts/license_quorum.py` in GenLayer Studio. Call `assess_license_usage` with commit-pinned public license/manifest URLs from at least two hosts. Wait for a consensus-accepted transaction, then call `get_latest_receipt_id` and `get_receipt` to inspect the persisted `lic_*` record.

## Validation

```bash
npm test
```
