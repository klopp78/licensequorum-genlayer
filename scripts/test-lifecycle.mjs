import fs from "node:fs";

const source = fs.readFileSync(new URL("../contracts/license_quorum.py", import.meta.url), "utf8");
const lifecycle = ["_validate_urls", "_source_manifest", "_evaluate", "_parse_result", "self.receipts[receipt_id]", "self.receipt_ids.append(receipt_id)", "self.latest_receipt_id = receipt_id"];
for (const control of lifecycle) {
  if (!source.includes(control)) throw new Error(`Lifecycle control missing: ${control}`);
}
console.log("LicenseQuorum lifecycle checks passed");
