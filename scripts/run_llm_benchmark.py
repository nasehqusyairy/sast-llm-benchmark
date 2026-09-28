#!/usr/bin/env python3

import argparse
import json
import os
import re
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone


OLLAMA_URL = "http://localhost:11434/api/generate"

SYSTEM_PROMPT = """You are a source-code security analyzer.

Analyze Java source code for security vulnerabilities.

Your task is to determine whether the provided source code contains a real security vulnerability.

Return ONLY valid JSON with exactly these fields:
{
  "vulnerable": true,
  "cwe": "CWE-22",
  "line": 42,
  "reason": "brief explanation"
}

Rules:
- "vulnerable" must be boolean.
- "cwe" must contain the most likely CWE identifier as a string, or null if uncertain.
- "line" must contain the most relevant source-code line number as an integer, or null if uncertain.
- "reason" must briefly explain the security issue.
- Do not include Markdown.
- Do not include additional fields.
"""


def call_ollama(model: str, prompt: str, timeout: int):
    payload = {
        "model": model,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "think": False,
        "options": {
            "temperature": 0
        }
    }

    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    start = time.perf_counter()

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))

        elapsed = time.perf_counter() - start

        return {
            "success": True,
            "response": body.get("response", ""),
            "elapsed_seconds": round(elapsed, 3),
            "error": None,
        }

    except Exception as exc:
        elapsed = time.perf_counter() - start

        return {
            "success": False,
            "response": "",
            "elapsed_seconds": round(elapsed, 3),
            "error": str(exc),
        }


def parse_json_response(response: str):
    response = response.strip()

    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    # Fallback in case the model accidentally surrounds JSON with text.
    match = re.search(r"\{.*\}", response, re.DOTALL)

    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return None


REQUIRED_FIELD = "vulnerable"
OPTIONAL_FIELDS = ("cwe", "line", "reason")


def validate_schema(parsed):
    """
    Checks the parsed JSON against the expected schema.

    Only "vulnerable" (boolean) is required for the primary metric.
    "cwe", "line", "reason" are optional extras used for secondary
    analysis; if missing, they are filled with None and reported
    in missing_fields instead of causing a failure.

    Returns (schema_valid, missing_fields, normalized_parsed).
    """
    if not isinstance(parsed, dict):
        return False, [REQUIRED_FIELD] + list(OPTIONAL_FIELDS), parsed

    missing_fields = []

    if REQUIRED_FIELD not in parsed or not isinstance(parsed[REQUIRED_FIELD], bool):
        missing_fields.append(REQUIRED_FIELD)

    normalized = dict(parsed)

    for field in OPTIONAL_FIELDS:
        if field not in normalized:
            normalized[field] = None
            missing_fields.append(field)

    schema_valid = REQUIRED_FIELD not in missing_fields

    return schema_valid, missing_fields, normalized


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--dataset",
        default="llm/dataset.jsonl",
    )

    parser.add_argument(
        "--model",
        default="qwen2.5:3b",
    )

    parser.add_argument(
        "--output",
        default="results/llm/raw/results.jsonl",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only process the first N records.",
    )

    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip test cases already present in the output file.",
    )

    args = parser.parse_args()

    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    completed = set()

    if args.resume and os.path.exists(args.output):
        with open(args.output, encoding="utf-8") as f:
            for line in f:
                try:
                    record = json.loads(line)
                    completed.add(record["test_name"])
                except Exception:
                    continue

        print(f"Already completed : {len(completed)}")

    dataset = []

    with open(args.dataset, encoding="utf-8") as f:
        for line in f:
            dataset.append(json.loads(line))

    if args.limit is not None:
        dataset = dataset[:args.limit]

    print(f"Model              : {args.model}")
    print(f"Dataset records    : {len(dataset)}")
    print(f"Output             : {args.output}")
    print()

    with open(args.output, "a", encoding="utf-8") as output:
        for index, item in enumerate(dataset, start=1):

            test_name = item["test_name"]

            if test_name in completed:
                continue

            code = item["code"]

            prompt = f"""Analyze the following Java source code.

Source code:
```java
{code}
```

Determine whether this source code contains a security vulnerability.
"""

            result = call_ollama(
                model=args.model,
                prompt=prompt,
                timeout=args.timeout,
            )

            parsed = (
                parse_json_response(result["response"])
                if result["success"]
                else None
            )

            if parsed is not None:
                schema_valid, missing_fields, parsed = validate_schema(parsed)
            else:
                schema_valid, missing_fields = False, [REQUIRED_FIELD] + list(OPTIONAL_FIELDS)

            record = {
                "test_name": test_name,
                "model": args.model,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "success": result["success"],
                "elapsed_seconds": result["elapsed_seconds"],
                "raw_response": result["response"],
                "parsed": parsed,
                "schema_valid": schema_valid,
                "missing_fields": missing_fields,
                "error": result["error"],
            }

            output.write(json.dumps(record, ensure_ascii=False) + "\n")
            output.flush()

            if parsed is None:
                status = "PARSE_ERROR"
            elif not schema_valid:
                status = "SCHEMA_INVALID"
            elif missing_fields:
                status = "OK (missing: " + ",".join(missing_fields) + ")"
            else:
                status = "OK"

            print(
                f"[{index}/{len(dataset)}] "
                f"{test_name} "
                f"{status} "
                f"{result['elapsed_seconds']:.2f}s"
            )


if __name__ == "__main__":
    main()