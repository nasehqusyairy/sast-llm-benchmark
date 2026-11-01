#!/usr/bin/env python3
"""
Normalize LLM experiment JSONL + summary files.

Input:
    results/llm/raw/*.jsonl
    results/llm/raw/*.summary.json

Output:
    results/llm/raw/normalized/*.summary.json

Original files are never modified.
"""

import json
from pathlib import Path
from collections import Counter


RAW_DIR = Path("results/llm/raw")
OUTPUT_DIR = RAW_DIR / "normalized"

# CWE aliases observed in the experiment output.
CWE_ALIASES = {
    "sqli": "89",
    "pathtraver": "22",
    "weakrand": "330",
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path: Path):
    records = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"JSONL invalid pada {path}:{line_number}: {exc}"
                ) from exc

    return records


def normalize_cwe(value):
    """
    Normalize CWE format when a known normalization is possible.

    Returns:
        (normalized_value, was_changed)

    Rules:
    - None or empty value -> empty string.
    - Numeric CWE ID -> unchanged.
    - CWE-89 -> 89.
    - Known aliases -> mapped numeric CWE ID.
    - Unknown/non-numeric CWE -> preserved as-is.

    An unknown CWE does not make the binary prediction invalid.
    """
    if value is None:
        return "", False

    value = str(value).strip()

    if value == "":
        return "", False

    # Already numeric CWE ID.
    if value.isdigit():
        return value, False

    # Normalize common CWE-ID format, e.g. CWE-89 -> 89.
    upper_value = value.upper()

    if upper_value.startswith("CWE-"):
        cwe_id = upper_value[4:].strip()

        if cwe_id.isdigit():
            return cwe_id, True

    # Known aliases.
    alias_key = value.lower()

    if alias_key in CWE_ALIASES:
        return CWE_ALIASES[alias_key], True

    # Unknown or out-of-scope CWE:
    # preserve it, but do not mark the binary prediction invalid.
    return value, False


def normalize_record(record):
    """
    Normalize parsed model output.

    A record is considered valid when:
    - model call succeeded,
    - parsed output is a dictionary,
    - vulnerable is a boolean,
    - line is None or an integer,
    - reason is a string.

    CWE format or CWE label-space membership does not determine
    binary prediction validity.
    """
    normalized = dict(record)

    parsed = record.get("parsed")

    if not isinstance(parsed, dict):
        parsed = record.get("parsed_raw")

    if not isinstance(parsed, dict):
        normalized["schema_valid"] = False
        normalized["missing_fields"] = [
            "parsed output is not an object"
        ]
        normalized["error"] = "SCHEMA_INVALID"
        return normalized, False, False

    parsed = dict(parsed)

    original_cwe = parsed.get("cwe")
    cwe, cwe_changed = normalize_cwe(original_cwe)
    parsed["cwe"] = cwe

    vulnerable = parsed.get("vulnerable")
    line = parsed.get("line")
    reason = parsed.get("reason")

    schema_valid = (
        record.get("success") is True
        and isinstance(vulnerable, bool)
        and (line is None or isinstance(line, int))
        and isinstance(reason, str)
    )

    normalized["parsed"] = parsed

    # Keep parsed_raw synchronized with normalized parsed output.
    # raw_response remains unchanged for traceability.
    normalized["parsed_raw"] = parsed

    if cwe_changed:
        changes = list(normalized.get("resolver_changes") or [])

        changes.append({
            "field": "cwe",
            "from": original_cwe,
            "to": cwe,
            "normalization": "CWE_FORMAT_OR_ALIAS_NORMALIZATION",
        })

        normalized["resolver_changes"] = changes

    normalized["schema_valid"] = schema_valid
    normalized["missing_fields"] = []

    if not isinstance(vulnerable, bool):
        normalized["missing_fields"].append(
            "vulnerable(boolean)"
        )

    if line is not None and not isinstance(line, int):
        normalized["missing_fields"].append(
            "line(integer or null)"
        )

    if not isinstance(reason, str):
        normalized["missing_fields"].append(
            "reason(string)"
        )

    normalized["error"] = (
        None if schema_valid else "SCHEMA_INVALID"
    )

    return normalized, schema_valid, cwe_changed


def build_summary(original_summary, records):
    predictions = []
    cwe_distribution = Counter()

    valid_count = 0
    invalid_count = 0
    vulnerable_count = 0
    non_vulnerable_count = 0
    vulnerable_with_cwe = 0
    normalized_alias_count = 0

    for record in records:
        normalized_record, is_valid, cwe_changed = normalize_record(
            record
        )

        if cwe_changed:
            normalized_alias_count += 1

        if not is_valid:
            invalid_count += 1
            continue

        valid_count += 1
        parsed = normalized_record["parsed"]

        prediction = {
            "test_name": normalized_record.get("test_name"),
            "vulnerable": parsed["vulnerable"],
            "cwe": parsed.get("cwe", ""),
            "line": parsed.get("line"),
            "reason": parsed.get("reason", ""),
        }

        predictions.append(prediction)

        if prediction["vulnerable"]:
            vulnerable_count += 1

            if prediction["cwe"]:
                vulnerable_with_cwe += 1
                cwe_distribution[prediction["cwe"]] += 1
        else:
            non_vulnerable_count += 1

    result = dict(original_summary)

    result.update({
        "dataset_records": len(records),
        "predictions_valid": valid_count,
        "vulnerable_detected_by_model": vulnerable_count,
        "classified_not_vulnerable_by_model": non_vulnerable_count,
        "vulnerable_predictions_with_cwe": vulnerable_with_cwe,
        "cwe_distribution": dict(
            sorted(cwe_distribution.items())
        ),
        "missing_predictions": max(
            0,
            len(records) - valid_count - invalid_count
        ),
        "invalid_responses": invalid_count,
        "failed_calls": sum(
            1
            for record in records
            if record.get("success") is not True
        ),
        "missing_sample_ids": [],
        "predictions": predictions,
        "normalization": {
            "method": (
                "Normalize known CWE formats and aliases; "
                "preserve unknown CWE values"
            ),
            "aliases": CWE_ALIASES,
            "normalized_alias_records": normalized_alias_count,
            "invalid_records_remaining": invalid_count,
            "unknown_cwe_values_preserved": True,
        },
    })

    return result


def process_pair(jsonl_path: Path, summary_path: Path):
    records = load_jsonl(jsonl_path)
    original_summary = load_json(summary_path)

    normalized_summary = build_summary(
        original_summary,
        records,
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    output_path = OUTPUT_DIR / summary_path.name

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(
            normalized_summary,
            f,
            ensure_ascii=False,
            indent=2,
        )
        f.write("\n")

    print(
        f"[OK] {jsonl_path.name}\n"
        f"     Valid: "
        f"{normalized_summary['predictions_valid']}/"
        f"{normalized_summary['dataset_records']}\n"
        f"     Invalid: "
        f"{normalized_summary['invalid_responses']}\n"
        f"     CWE formats normalized: "
        f"{normalized_alias_count(normalized_summary)}\n"
        f"     Output: {output_path}\n"
    )


def normalized_alias_count(summary):
    return summary.get(
        "normalization", {}
    ).get(
        "normalized_alias_records", 0
    )


def main():
    if not RAW_DIR.exists():
        raise SystemExit(
            f"Folder tidak ditemukan: {RAW_DIR}"
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    jsonl_files = sorted(
        path
        for path in RAW_DIR.glob("*.jsonl")
        if path.is_file()
    )

    processed = 0
    skipped = 0

    for jsonl_path in jsonl_files:
        # Example:
        # model__scenario.jsonl
        # model__scenario.summary.json
        summary_path = jsonl_path.with_name(
            f"{jsonl_path.stem}.summary.json"
        )

        if not summary_path.exists():
            print(
                f"[SKIP] Summary tidak ditemukan untuk "
                f"{jsonl_path.name}: {summary_path.name}"
            )
            skipped += 1
            continue

        try:
            process_pair(jsonl_path, summary_path)
            processed += 1
        except Exception as exc:
            print(
                f"[ERROR] {jsonl_path.name}: {exc}"
            )
            skipped += 1

    print("Selesai.")
    print(f"Pasangan diproses: {processed}")
    print(f"Dilewati/error: {skipped}")
    print(f"Folder output: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()