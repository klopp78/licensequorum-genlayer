# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""Consensus license-usage receipts with source-bound evidence commitments."""

from genlayer import *
import hashlib
import json
import typing


class LicenseQuorum(gl.Contract):
    """Append-only, independently checked license-usage decisions."""

    receipt_count: u64
    latest_receipt_id: str
    receipt_ids: DynArray[str]
    receipts: TreeMap[str, str]

    def __init__(self):
        self.receipt_count = u64(0)
        self.latest_receipt_id = ""

    @gl.public.view
    def get_receipt_count(self) -> u64:
        return self.receipt_count

    @gl.public.view
    def get_latest_receipt_id(self) -> str:
        return self.latest_receipt_id

    @gl.public.view
    def get_receipt(self, receipt_id: str) -> str:
        return self.receipts.get(receipt_id.strip(), "")

    @gl.public.view
    def list_receipt_ids(self) -> str:
        return json.dumps([item for item in self.receipt_ids], separators=(",", ":"))

    @gl.public.write
    def assess_license_usage(
        self,
        package_name: str,
        package_version: str,
        requested_use: str,
        source_urls: DynArray[str],
    ) -> str:
        package = _package_name(package_name)
        version = _version(package_version)
        use = _requested_use(requested_use)
        urls = _validate_urls([url for url in source_urls])
        manifest = _source_manifest(urls)
        if len({item["host"] for item in manifest}) < 2:
            raise Exception("at_least_two_independent_hosts_required")

        context_hash = _sha256_parts([
            "licensequorum.v1",
            package,
            version,
            use,
            _canonical_json(manifest),
        ])

        def leader_fn():
            return _evaluate(package, version, use, urls, manifest, context_hash)

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                proposed = _parse_result(leader_result.calldata)
                independent = _parse_result(_evaluate(package, version, use, urls, manifest, context_hash))
            except Exception:
                return False
            return (
                proposed["decision"] == independent["decision"]
                and proposed["license_ids"] == independent["license_ids"]
                and proposed["obligations"] == independent["obligations"]
                and proposed["exact_package_match"] == independent["exact_package_match"]
                and proposed["exact_version_match"] == independent["exact_version_match"]
                and proposed["readable_source_count"] == independent["readable_source_count"]
                and proposed["source_snapshot_hashes"] == independent["source_snapshot_hashes"]
                and proposed["snapshot_bundle_hash"] == independent["snapshot_bundle_hash"]
                and proposed["license_context_hash"] == independent["license_context_hash"]
                and abs(proposed["confidence"] - independent["confidence"]) <= 10
            )

        result = _parse_result(gl.vm.run_nondet_unsafe(leader_fn, validator_fn))
        self.receipt_count = u64(int(self.receipt_count) + 1)
        sequence = int(self.receipt_count)
        receipt_id = "lic_" + _sha256_parts([context_hash, result["snapshot_bundle_hash"], str(sequence)])[:20]
        record = {
            "schema_version": "licensequorum.v1",
            "receipt_id": receipt_id,
            "sequence": sequence,
            "package_name": package,
            "package_version": version,
            "requested_use": use,
            "license_context_hash": context_hash,
            "source_manifest": manifest,
            "source_snapshot_hashes": result["source_snapshot_hashes"],
            "snapshot_bundle_hash": result["snapshot_bundle_hash"],
            "submitted_by": str(gl.message.sender_address).lower(),
            "decision": result["decision"],
            "confidence": result["confidence"],
            "exact_package_match": result["exact_package_match"],
            "exact_version_match": result["exact_version_match"],
            "license_ids": result["license_ids"],
            "obligations": result["obligations"],
            "readable_source_count": result["readable_source_count"],
        }
        record_hash = _sha256(_canonical_json(record))
        record["accepted_write"] = {
            "receipt_id": receipt_id,
            "record_hash": record_hash,
            "snapshot_bundle_hash": result["snapshot_bundle_hash"],
        }
        self.receipts[receipt_id] = _canonical_json(record)
        self.receipt_ids.append(receipt_id)
        self.latest_receipt_id = receipt_id
        return receipt_id


def _evaluate(
    package: str,
    version: str,
    requested_use: str,
    urls: typing.Sequence[str],
    manifest: typing.Sequence[dict],
    context_hash: str,
) -> str:
    snapshots = []
    snapshot_hashes = []
    readable_count = 0
    for index, url in enumerate(urls):
        try:
            rendered = gl.nondet.web.render(url, mode="text")[:9000]
            readable = len(rendered.strip()) >= 40
        except Exception:
            rendered = "SOURCE_UNAVAILABLE"
            readable = False
        if readable:
            readable_count += 1
        snapshot_hash = _sha256(rendered)
        snapshot_hashes.append(snapshot_hash)
        snapshots.append({
            "source_index": index + 1,
            "host": manifest[index]["host"],
            "url": url,
            "readable": readable,
            "snapshot_hash": snapshot_hash,
            "text": rendered,
        })

    bundle_hash = _sha256_parts([context_hash, _canonical_json(snapshot_hashes)])
    if readable_count < 2:
        return _canonical_json({
            "decision": "needs_review",
            "confidence": 100,
            "exact_package_match": False,
            "exact_version_match": False,
            "license_ids": [],
            "obligations": [],
            "readable_source_count": readable_count,
            "source_snapshot_hashes": snapshot_hashes,
            "snapshot_bundle_hash": bundle_hash,
            "license_context_hash": context_hash,
        })

    prompt = f"""
You are a software license-usage adjudicator. Decide whether the exact named package and version
can be used for the requested use, only from independently rendered public sources. Do not infer
permissions from a repository that does not clearly identify the package/version. Return
needs_review whenever license terms, scope, attribution, redistribution, source-disclosure, or
commercial-use facts are ambiguous or conflict.

Package: {package}
Version: {version}
Requested use: {requested_use}
Source manifest: {_canonical_json(manifest)}
Rendered evidence: {_canonical_json(snapshots)}

Return only minified JSON with exactly these fields:
decision (allowed|restricted|needs_review), confidence (0-100), exact_package_match (boolean),
exact_version_match (boolean), license_ids (sorted array of up to 8 identifiers such as MIT,
Apache-2.0, GPL-3.0-only), and obligations (sorted array of up to 8 short machine-readable terms
such as attribution, include_license, disclose_source, no_commercial_use, notice). No prose or
additional fields.
"""
    model_result = json.loads(gl.nondet.exec_prompt(prompt))
    parsed = _parse_model_fields(model_result)
    parsed.update({
        "readable_source_count": readable_count,
        "source_snapshot_hashes": snapshot_hashes,
        "snapshot_bundle_hash": bundle_hash,
        "license_context_hash": context_hash,
    })
    return _canonical_json(parsed)


def _parse_model_fields(raw: dict) -> dict:
    decision = str(raw.get("decision", "")).lower()
    if decision not in ("allowed", "restricted", "needs_review"):
        raise Exception("invalid_decision")
    confidence = int(raw.get("confidence", -1))
    if confidence < 0 or confidence > 100:
        raise Exception("invalid_confidence")
    package_match = raw.get("exact_package_match")
    version_match = raw.get("exact_version_match")
    if not isinstance(package_match, bool) or not isinstance(version_match, bool):
        raise Exception("invalid_match_flags")
    licenses = _tokens(raw.get("license_ids", []), 8, "invalid_license_ids")
    obligations = _tokens(raw.get("obligations", []), 8, "invalid_obligations")
    if decision == "allowed" and (not package_match or not version_match):
        raise Exception("allowed_requires_exact_match")
    return {
        "decision": decision,
        "confidence": confidence,
        "exact_package_match": package_match,
        "exact_version_match": version_match,
        "license_ids": licenses,
        "obligations": obligations,
    }


def _parse_result(raw: str) -> dict:
    result = json.loads(raw)
    parsed = _parse_model_fields(result)
    hashes = result.get("source_snapshot_hashes", [])
    if not isinstance(hashes, list) or len(hashes) < 2 or len(hashes) > 5:
        raise Exception("invalid_snapshot_hashes")
    if any(not _is_digest(str(item)) for item in hashes):
        raise Exception("invalid_snapshot_hash")
    readable_count = int(result.get("readable_source_count", -1))
    if readable_count < 0 or readable_count > len(hashes):
        raise Exception("invalid_readable_source_count")
    bundle_hash = str(result.get("snapshot_bundle_hash", ""))
    context_hash = str(result.get("license_context_hash", ""))
    if not _is_digest(bundle_hash) or not _is_digest(context_hash):
        raise Exception("invalid_commitment")
    parsed.update({
        "readable_source_count": readable_count,
        "source_snapshot_hashes": [str(item) for item in hashes],
        "snapshot_bundle_hash": bundle_hash,
        "license_context_hash": context_hash,
    })
    return parsed


def _validate_urls(raw_urls: typing.Sequence[str]) -> typing.Sequence[str]:
    if len(raw_urls) < 2 or len(raw_urls) > 5:
        raise Exception("use_two_to_five_sources")
    urls = []
    seen = set()
    for raw in raw_urls:
        url = str(raw).strip()
        key = url.rstrip("/").lower()
        if not url.startswith("https://") or len(url) > 600:
            raise Exception("invalid_source_url")
        if key in seen:
            raise Exception("duplicate_source_url")
        seen.add(key)
        urls.append(url)
    return urls


def _source_manifest(urls: typing.Sequence[str]) -> typing.Sequence[dict]:
    return [{"source_index": index + 1, "url": url, "host": _host(url), "url_hash": _sha256(url)} for index, url in enumerate(urls)]


def _host(url: str) -> str:
    host = url.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    if "." not in host or len(host) > 253:
        raise Exception("invalid_source_host")
    return host


def _package_name(raw: str) -> str:
    value = str(raw).strip().lower()
    if len(value) < 2 or len(value) > 160 or any(char in value for char in "\n\r\t"):
        raise Exception("invalid_package_name")
    return value


def _version(raw: str) -> str:
    value = str(raw).strip()
    if len(value) < 1 or len(value) > 100 or any(char in value for char in "\n\r\t"):
        raise Exception("invalid_version")
    return value


def _requested_use(raw: str) -> str:
    value = " ".join(str(raw).strip().split())
    if len(value) < 8 or len(value) > 360:
        raise Exception("invalid_requested_use")
    return value


def _tokens(raw, maximum: int, error: str) -> typing.Sequence[str]:
    if not isinstance(raw, list) or len(raw) > maximum:
        raise Exception(error)
    values = []
    for item in raw:
        value = str(item).strip().lower()
        if len(value) < 2 or len(value) > 60 or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789.+-_" for char in value):
            raise Exception(error)
        if value not in values:
            values.append(value)
    return sorted(values)


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _canonical_parts(parts: typing.Sequence[str]) -> str:
    return "".join(str(len(str(part))) + ":" + str(part) for part in parts)


def _sha256_parts(parts: typing.Sequence[str]) -> str:
    return _sha256(_canonical_parts(parts))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)
