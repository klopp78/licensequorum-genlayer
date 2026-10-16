import fs from "node:fs";

const source = fs.readFileSync(new URL("../contracts/license_quorum.py", import.meta.url), "utf8");
const required = [
  "class LicenseQuorum",
  "assess_license_usage",
  "get_receipt",
  "list_receipt_ids",
  "hashlib.sha256",
  "_canonical_parts",
  "license_context_hash",
  "source_snapshot_hashes",
  "snapshot_bundle_hash",
  "at_least_two_independent_hosts_required",
  'proposed["decision"] == independent["decision"]',
  'proposed["license_ids"] == independent["license_ids"]',
  'proposed["obligations"] == independent["obligations"]',
  'proposed["source_snapshot_hashes"] == independent["source_snapshot_hashes"]',
];

for (const control of required) {
  if (!source.includes(control)) throw new Error(`Missing required control: ${control}`);
}
for (const weakPattern of ["hash(", "leader_result.calldata ==", "md5"]) {
  if (source.includes(weakPattern)) throw new Error(`Weak pattern found: ${weakPattern}`);
}
console.log("LicenseQuorum structure checks passed");
