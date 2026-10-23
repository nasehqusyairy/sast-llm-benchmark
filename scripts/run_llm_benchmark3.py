#!/usr/bin/env python3
"""Interactive, scenario-aware OWASP Benchmark runner backed by Ollama.

Designed to live at scripts/run_llm_benchmark.py in sast-llm-benchmark.
Reads prompt templates from ../prompts (copied from Experiment-SAST-LLM-Tools)
when available. Logs every attempt as JSONL under results/llm/raw/.

Dataset JSONL records must contain: test_name, code. Optional: cwe, category.
Ground-truth outcome labels are intentionally never inserted into prompts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import subprocess
import xml.etree.ElementTree as ET
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "llm" / "dataset.jsonl"
OUTPUT_DIR = ROOT / "results" / "llm" / "raw"
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
DEFAULT_TIMEOUT = 300
DEFAULT_LIMIT: int | None = None
BENCHMARK_ROOT = ROOT / "benchmark" / "BenchmarkJava"
SAST_REPORT_HASH = ""

# The names map to the prompt filenames from Experiment-SAST-LLM-Tools.
# Template strings are loaded from disk first; fallback values keep the runner
# usable before the prompt folder is copied, but a visible warning is printed.
SCENARIOS: list[dict[str, Any]] = [
    {"id":"baseline-1", "label":"baseline-1", "prompt_id":"baseline-1", "sast":"none", "think":False, "template":"baseline_1.txt", "system":"You are a source-code security analyzer. Analyze Java code for security vulnerabilities. Return only valid JSON with fields vulnerable (boolean), cwe (string or null), line (integer or null), and reason (string). Do not include Markdown."},
    {"id":"baseline-2", "label":"baseline-2", "prompt_id":"baseline-2", "sast":"findsecbugs", "think":False, "template":"baseline_2.txt", "system":"You are a source-code security analyzer. Analyze Java code and the provided FindSecBugs results. Return only valid JSON with fields vulnerable (boolean), cwe (string or null), line (integer or null), and reason (string). Do not include Markdown."},
    {"id":"zero-shot-none", "label":"zero-shot (LLM-only)", "prompt_id":"zero-shot", "sast":"none", "think":False, "template":"munson_adaptations/zero_shot_none_v1.txt", "fallback_template":"zero_shot.txt", "system":"You are a source-code security analyzer. Follow the supplied analysis instructions. Return only the required structured output; do not include Markdown."},
    {"id":"zero-shot-findsecbugs", "label":"zero-shot + FindSecBugs", "prompt_id":"zero-shot", "sast":"findsecbugs", "think":False, "template":"munson_adaptations/zero_shot_findsecbugs_v1.txt", "fallback_template":"zero_shot.txt", "system":"You are a source-code security analyzer. Follow the supplied analysis instructions and consider the FindSecBugs context. Return only the required structured output; do not include Markdown."},
    {"id":"cot-none", "label":"CoT (LLM-only)", "prompt_id":"cot", "sast":"none", "think":False, "template":"munson_adaptations/cot_none_v1.txt", "fallback_template":"cot.txt", "system":"You are a source-code security analyzer. Follow the supplied analysis instructions. Return only the required structured output; do not include Markdown."},
    {"id":"cot-findsecbugs", "label":"CoT + FindSecBugs", "prompt_id":"cot", "sast":"findsecbugs", "think":False, "template":"munson_adaptations/cot_findsecbugs_v1.txt", "fallback_template":"cot.txt", "system":"You are a source-code security analyzer. Follow the supplied analysis instructions and consider the FindSecBugs context. Return only the required structured output; do not include Markdown."},
    {"id":"tot-none", "label":"ToT (LLM-only)", "prompt_id":"tot", "sast":"none", "think":False, "template":"munson_adaptations/tot_none_v2.txt", "fallback_template":"tot.txt", "system":"You are a source-code security analyzer. Follow the supplied analysis instructions. Return only the required structured output; do not include Markdown."},
    {"id":"tot-findsecbugs", "label":"ToT + FindSecBugs", "prompt_id":"tot", "sast":"findsecbugs", "think":False, "template":"munson_adaptations/tot_findsecbugs_v2.txt", "fallback_template":"tot.txt", "system":"You are a source-code security analyzer. Follow the supplied analysis instructions and consider the FindSecBugs context. Return only the required structured output; do not include Markdown."},
]
MODELS = ["deepseek-coder:6.7b", "qwen2.5-coder:7b", "gemma4:e4b"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.") or "scenario"


def load_templates(scenario: dict[str, Any]) -> tuple[str, str, str | None]:
    """Return (template, relative template name, warning)."""
    # Run from repository root or from scripts/: find the moved prompt folder.
    candidates_dirs = [ROOT / "prompts", Path.cwd() / "prompts", Path.cwd().parent / "prompts"]
    prompt_dir = next((p for p in candidates_dirs if p.is_dir()), ROOT / "prompts")
    candidates = [scenario["template"]]
    if scenario.get("fallback_template"):
        candidates.append(scenario["fallback_template"])
    for name in candidates:
        path = prompt_dir / name
        if path.is_file():
            try: display_path = str(path.relative_to(ROOT))
            except ValueError: display_path = str(path)
            return path.read_text(encoding="utf-8"), display_path, None if name == candidates[0] else f"Template {scenario['template']} tidak ditemukan; fallback ke {name}."
    fallback = """Analyze this Java source code for security vulnerabilities.\n\nJava source:\n```java\n{JAVA_SOURCE_CODE}\n```\n\nTarget CWE: {CWE_NAME}\nFindSecBugs context:\n{SAST_CONTEXT}\n\nReturn only JSON: {\"vulnerable\": true or false, \"cwe\": \"CWE-n\" or \"\", \"line\": integer or null, \"reason\": \"brief explanation\"}."""
    return fallback, "<built-in-fallback>", f"Prompt tidak ditemukan untuk skenario {scenario['id']}; menggunakan fallback generik. Untuk penelitian final, salin folder prompts dari Experiment-SAST-LLM-Tools."


def render_template(template: str, item: dict[str, Any], scenario: dict[str, Any]) -> str:
    """Render supported placeholders; never pass ground-truth outcome to model."""
    code = item.get("code", item.get("java_source", ""))
    if not isinstance(code, str) or not code.strip():
        raise ValueError(f"Sampel {item.get('test_name', item.get('sample_id', '?'))} tidak memiliki source code.")
    # Dataset CWE is target-task metadata for Munson configurations only, not the vulnerable/benign label.
    raw_cwe = item.get("cwe", item.get("target_cwe", ""))
    cwe_name = str(raw_cwe).strip()
    if cwe_name and not cwe_name.upper().startswith("CWE-"):
        cwe_name = "CWE-" + cwe_name
    if scenario["prompt_id"] in {"zero-shot", "cot", "tot"} and not cwe_name:
        raise ValueError(f"Sampel {item.get('test_name', item.get('sample_id', '?'))} tidak memiliki CWE target; menolak menebak CWE.")
    sast_context = item.get("findsecbugs_context", item.get("sast_context", ""))
    if scenario["sast"] == "findsecbugs" and not str(sast_context).strip():
        raise ValueError("Skenario FindSecBugs dipilih tetapi dataset tidak menyediakan findsecbugs_context. Tidak ada hasil scanner yang akan direkayasa.")
    values = {
        "JAVA_SOURCE_CODE": code,
        "java_code": code,
        "CWE_NAME": cwe_name,
        "cwe_name": cwe_name,
        "SAST_CONTEXT": str(sast_context) if scenario["sast"] == "findsecbugs" else "",
        "sast_context": str(sast_context) if scenario["sast"] == "findsecbugs" else "",
        "SYSTEM_INSTRUCTIONS": scenario["system"],
        "ADDITIONAL_INSTRUCTIONS": "Use only concise evidence in the final reason; do not reveal hidden chain-of-thought.",
    }
    # Check the template itself before inserting source code. Scanning the fully
    # rendered prompt is unsafe: Java source can legitimately contain tokens such
    # as {cmd} or {param}, which are not prompt placeholders.
    unresolved_template = re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", template)
    unknown_template = sorted(set(unresolved_template) - set(values))
    if unknown_template:
        raise ValueError(
            "Placeholder prompt tidak didukung/tidak terisi pada file template: "
            f"{unknown_template}"
        )

    # Replace known placeholders literally; avoid str.format because Java source
    # and JSON examples may contain braces.
    result = template
    for key, value in values.items():
        result = result.replace("{" + key + "}", str(value))
    return result


def call_ollama(model: str, system: str, prompt: str, *, timeout: int, think: bool, options: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"model": model, "system": system, "prompt": prompt, "stream": False, "format": "json", "think": think, "options": options}
    req = urllib.request.Request(OLLAMA_URL, data=json.dumps(payload).encode(), headers={"Content-Type":"application/json"}, method="POST")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw_body = response.read().decode("utf-8")
        envelope = json.loads(raw_body)
        return {"success": True, "response": envelope.get("response", ""), "thinking": envelope.get("thinking", ""), "elapsed_seconds": round(time.perf_counter()-started, 3), "error": None, "http_envelope": envelope}
    except Exception as exc:
        return {"success": False, "response":"", "thinking":"", "elapsed_seconds":round(time.perf_counter()-started,3), "error":str(exc), "http_envelope":None}


def parse_json_response(response: str, config_id: str | None = None) -> Any:
    response = response.strip()
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", response, re.DOTALL)
        if match:
            try: return json.loads(match.group(0))
            except json.JSONDecodeError: pass
    # Compatibility with runExperiment.py / legacy prompts that return Q1-Q4 text.
    q1 = re.search(r"(?im)^\s*Q1\s*:\s*(TRUE|FALSE)\b", response)
    q2 = re.search(r"(?im)^\s*Q2\s*:\s*([^\r\n]+)", response)
    q3 = re.search(r"(?im)^\s*Q3\s*:\s*(\d+|N/?A|NONE)\b", response)
    q4 = re.search(r"(?im)^\s*Q4\s*:\s*(CWE-?\d+|\d+|N/?A|NONE)\b", response)
    q5 = re.search(r"(?im)^\s*Q5\s*:\s*(TP|FP)\b", response)
    if all((q1, q2, q3, q4)) and (config_id != "baseline-2" or q5):
        return {"Q1": q1.group(1).upper() == "TRUE", "Q2": q2.group(1).strip(), "Q3": q3.group(1), "Q4": q4.group(1), **({"Q5": q5.group(1).upper()} if q5 else {})}
    return None


def resolve_prediction(parsed: Any) -> tuple[Any, list[dict[str, Any]]]:
    """Deterministic, auditable cleanup of common formatting variations before schema validation.

    This resolver fixes representation only; it does not guess a CWE from prose or change
    the model's vulnerability judgment, because semantic rewriting would bias the benchmark.
    """
    if not isinstance(parsed, dict):
        return parsed, []
    resolved = dict(parsed)
    changes: list[dict[str, Any]] = []

    def replace_value(key: str, new_value: Any, reason: str) -> None:
        old_value = resolved.get(key)
        if old_value != new_value:
            resolved[key] = new_value
            changes.append({"field": key, "from": old_value, "to": new_value, "rule": reason})

    # Normalize common boolean representations.
    value = resolved.get("vulnerable")
    if isinstance(value, str):
        token = value.strip().lower()
        if token in {"true", "yes", "1", "vulnerable"}:
            replace_value("vulnerable", True, "boolean_string_to_boolean")
        elif token in {"false", "no", "0", "not vulnerable", "safe"}:
            replace_value("vulnerable", False, "boolean_string_to_boolean")

    # Canonicalize CWE formatting, e.g. 22, "cwe 22", "CWE-22", or "CWE-22: Path Traversal".
    value = resolved.get("cwe")
    if value is None:
        replace_value("cwe", "", "null_cwe_to_empty")
    elif isinstance(value, int) and not isinstance(value, bool) and value > 0:
        replace_value("cwe", f"CWE-{value}", "numeric_cwe_to_canonical")
    elif isinstance(value, str):
        token = value.strip()
        if token.lower() in {"", "n/a", "na", "none", "null", "unknown", "not applicable"}:
            replace_value("cwe", "", "empty_cwe_sentinel")
        else:
            match = re.fullmatch(r"(?i)CWE\s*-?\s*0*(\d+)(?:\s*[:;,\-].*)?", token)
            if match and int(match.group(1)) > 0:
                replace_value("cwe", f"CWE-{int(match.group(1))}", "cwe_format_canonicalization")
            elif re.fullmatch(r"\d+", token) and int(token) > 0:
                replace_value("cwe", f"CWE-{int(token)}", "numeric_string_cwe_to_canonical")

    # Line can arrive as a numeric string or as a simple "line 60" value.
    value = resolved.get("line")
    if isinstance(value, str):
        token = value.strip()
        if token.lower() in {"", "n/a", "na", "none", "null", "unknown"}:
            replace_value("line", None, "empty_line_sentinel")
        else:
            match = re.fullmatch(r"(?i)(?:line\s*)?(\d+)", token)
            if match and int(match.group(1)) > 0:
                replace_value("line", int(match.group(1)), "line_string_to_integer")

    # Preserve the original reason, but trim accidental outer whitespace.
    value = resolved.get("reason")
    if isinstance(value, str) and value != value.strip():
        replace_value("reason", value.strip(), "trim_reason_whitespace")
    return resolved, changes


def normalize_prediction(parsed: Any, config_id: str | None = None) -> tuple[bool, list[str], dict[str, Any] | None]:
    """Normalize strategy outputs from experiment_manager's Q1-Q4 and JSON contracts."""
    if not isinstance(parsed, dict):
        return False, ["vulnerable", "cwe", "line", "reason"], None
    if "vulnerable" not in parsed and "Q1" in parsed:
        q1 = parsed.get("Q1")
        if isinstance(q1, bool): vulnerable = q1
        elif isinstance(q1, str) and q1.strip().upper() in {"TRUE", "FALSE"}: vulnerable = q1.strip().upper() == "TRUE"
        else: return False, ["Q1 boolean/TRUE/FALSE"], None
        categories = {"pathtraver", "hash", "trustbound", "crypto", "cmdi", "sqli", "weakrand", "ldapi", "xss", "securecookie", "xpathi"}
        q2 = parsed.get("Q2", "")
        if not isinstance(q2, str) or q2.strip().lower() not in categories:
            return False, ["Q2 allowed vulnerability category"], None
        q3 = parsed.get("Q3")
        q4 = parsed.get("Q4", "")
        if config_id == "baseline-2":
            q5 = parsed.get("Q5")
            if not isinstance(q5, str) or q5.strip().upper() not in {"TP", "FP"} or (q5.strip().upper() == "TP") != vulnerable:
                return False, ["Q5 TP/FP consistent with Q1"], None
        cwe = str(q4).strip()
        if cwe and cwe.upper() not in {"N/A", "NA", "NONE", "NULL"}:
            m = re.fullmatch(r"CWE-?(\d+)|([1-9]\d*)", cwe, re.I)
            if not m or int(m.group(1) or m.group(2)) < 1:
                return False, ["Q4 valid positive CWE or N/A"], None
            cwe = "CWE-" + (m.group(1) or m.group(2))
        else: cwe = ""
        try: line = int(q3) if q3 not in (None, "", "N/A", "NA", "NONE") else None
        except (ValueError, TypeError): return False, ["Q3 positive line or N/A"], None
        if line is not None and line < 1: return False, ["Q3 positive line or N/A"], None
        parsed = {"vulnerable": vulnerable, "cwe": cwe, "line": line, "reason": ""}
    missing: list[str] = []
    if not isinstance(parsed.get("vulnerable"), bool):
        missing.append("vulnerable(boolean)")
    cwe_value = parsed.get("cwe", "")
    if cwe_value is None: cwe_value = ""
    if not isinstance(cwe_value, str): missing.append("cwe(string)")
    elif cwe_value:
        m = re.fullmatch(r"CWE-([1-9]\d*)", cwe_value, re.I)
        if not m: missing.append("cwe(canonical CWE-n or empty string)")
        else: cwe_value = "CWE-" + m.group(1)
    line = parsed.get("line")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
        missing.append("line(positive integer or null)")
    reason = parsed.get("reason", "")
    if reason is None: reason = ""
    if not isinstance(reason, str): missing.append("reason(string)")
    if parsed.get("vulnerable") is True and not cwe_value:
        missing.append("CWE required when vulnerable=true")
    if missing: return False, missing, None
    return True, [], {"vulnerable": parsed["vulnerable"], "cwe": cwe_value, "line": line, "reason": reason}


def read_dataset(path: Path) -> list[dict[str, Any]]:
    if not path.is_file(): raise FileNotFoundError(f"Dataset tidak ditemukan: {path}")
    rows = []
    with path.open(encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip(): continue
            try: item = json.loads(line)
            except json.JSONDecodeError as exc: raise ValueError(f"JSONL rusak di baris {n}: {exc}") from exc
            if not isinstance(item, dict): raise ValueError(f"Baris {n} bukan JSON object.")
            if not (item.get("test_name") or item.get("sample_id")): raise ValueError(f"Baris {n} tidak memiliki test_name/sample_id.")
            if not isinstance(item.get("code", item.get("java_source")), str): raise ValueError(f"Baris {n} tidak memiliki kode sumber.")
            rows.append(item)
    if not rows: raise ValueError("Dataset kosong.")
    ids = [str(r.get("test_name", r.get("sample_id"))) for r in rows]
    seen: set[str] = set()
    duplicate_set: set[str] = set()
    for sid in ids:
        if sid in seen: duplicate_set.add(sid)
        seen.add(sid)
    duplicates = sorted(duplicate_set)
    if duplicates: raise ValueError(f"ID sampel duplikat; contoh: {duplicates[:5]}")
    return rows


def output_path(scenario: dict[str, Any], model: str, dataset_hash: str, sast_hash: str | None = None) -> Path:
    think_label = "think-true" if scenario["think"] else "think-false"
    sast_suffix = f"__sast-{sast_hash[:12]}" if scenario.get("sast") == "findsecbugs" and sast_hash else ""
    name = f"{safe_name(model)}__{safe_name(scenario['id'])}__{think_label}__{dataset_hash[:12]}{sast_suffix}.jsonl"
    return OUTPUT_DIR / name


def read_completed(path: Path, scenario_id: str, model: str, dataset_hash: str, sast_hash: str | None = None) -> set[str]:
    completed: set[str] = set()
    if not path.exists(): return completed
    with path.open(encoding="utf-8") as f:
        for line in f:
            try: record = json.loads(line)
            except json.JSONDecodeError: continue
            same_sast = record.get("sast_report_sha256", "") == (sast_hash or "")
            if (record.get("scenario_id") == scenario_id and record.get("model") == model and record.get("dataset_sha256") == dataset_hash and same_sast and record.get("success") and record.get("schema_valid")):
                completed.add(str(record.get("test_name", "")))
    return completed


def load_ollama_models() -> tuple[set[str], str | None]:
    tags_url = OLLAMA_URL.rsplit("/api/generate", 1)[0] + "/api/tags"
    try:
        with urllib.request.urlopen(tags_url, timeout=5) as resp: body = json.loads(resp.read().decode())
        names = {m.get("name", "") for m in body.get("models", [])}
        return names, None
    except Exception as exc: return set(), str(exc)


def findsecbugs_script() -> Path:
    candidates = [
        BENCHMARK_ROOT / "scripts" / "runFindSecBugs.sh",
        BENCHMARK_ROOT / "script" / "runFindSecBugs.sh",
        BENCHMARK_ROOT / "runFindSecBugs.sh",
    ]
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError(
        "Script runFindSecBugs.sh tidak ditemukan. Pastikan repo OWASP berada di "
        f"{BENCHMARK_ROOT} dan memiliki scripts/runFindSecBugs.sh."
    )


def findsecbugs_reports() -> list[Path]:
    results_dir = BENCHMARK_ROOT / "results"
    if not results_dir.is_dir():
        return []
    candidates = [
        p for p in results_dir.rglob("*.xml")
        if ("findsecbugs" in p.name.lower()
            or ("findbugs" in p.name.lower() and "security" in p.name.lower())
            or "spotbugs" in p.name.lower())
    ]
    return sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)


def _xml_bug_text(node: ET.Element) -> str:
    parts = []
    for child in node.iter():
        value = (child.text or "").strip()
        if value:
            parts.append(value)
    return " ".join(dict.fromkeys(parts))


def parse_findsecbugs_xml(report: Path, rows: list[dict[str, Any]]) -> dict[str, str]:
    """Map SpotBugs/FindSecBugs BugInstance entries to BenchmarkTestNNNNN."""
    try:
        root = ET.parse(report).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ValueError(f"Laporan FindSecBugs tidak dapat dibaca ({report}): {exc}") from exc
    sample_ids = {str(r.get("test_name", r.get("sample_id", ""))) for r in rows}
    findings: dict[str, list[str]] = {sid: [] for sid in sample_ids}
    bug_count = 0
    for bug in root.iter():
        if bug.tag.rsplit("}", 1)[-1] != "BugInstance":
            continue
        bug_count += 1
        attrs = " ".join(str(v) for v in bug.attrib.values())
        blob = attrs + " " + _xml_bug_text(bug) + " " + ET.tostring(bug, encoding="unicode")
        ids = set(re.findall(r"BenchmarkTest\d{5}", blob, flags=re.IGNORECASE))
        if not ids:
            continue
        rule = bug.attrib.get("type", "UnknownRule")
        category = bug.attrib.get("category", "n/a")
        priority = bug.attrib.get("priority", "n/a")
        message = _xml_bug_text(bug)[:700] or rule
        line = ""
        for node in bug.iter():
            if node.tag.rsplit("}", 1)[-1] == "SourceLine":
                line = node.attrib.get("start", "") or line
        finding = f"rule={rule}; category={category}; priority={priority}; line={line or 'n/a'}; detail={message}"
        for sid in ids:
            if sid in findings:
                findings[sid].append(finding)
    if bug_count == 0:
        print("PERINGATAN: XML tidak berisi BugInstance; memeriksa validitas/kelengkapan laporan scanner.")
    return {
        sid: ("FindSecBugs melaporkan temuan:\n- " + "\n- ".join(items)) if items else
             ("FindSecBugs tidak melaporkan temuan untuk sampel ini pada laporan "
              f"{report.name}. Ini berarti tidak ada temuan di laporan, bukan bukti bahwa kode pasti aman.")
        for sid, items in findings.items()
    }


def ensure_findsecbugs_context(dataset_path: Path) -> tuple[list[dict[str, Any]], str]:
    rows = read_dataset(dataset_path)
    reports = findsecbugs_reports()
    if not reports:
        script = findsecbugs_script()
        print("\nLaporan FindSecBugs belum ditemukan. Menjalankan scanner OWASP Benchmark...")
        print(f"  Script: {script}")
        try:
            proc = subprocess.run(
                ["bash", str(script)], cwd=BENCHMARK_ROOT, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=3600, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            raise RuntimeError("FindSecBugs melewati batas 3600 detik. Output terakhir:\n" + output[-5000:])
        print(proc.stdout[-12000:] if proc.stdout else "(scanner tidak menghasilkan output teks)")
        if proc.returncode != 0:
            raise RuntimeError(f"runFindSecBugs.sh gagal (exit code {proc.returncode}). Periksa Java/Maven dan output di atas.")
        reports = findsecbugs_reports()
        if not reports:
            raise RuntimeError("Scanner selesai tetapi XML FindSecBugs tidak ditemukan di benchmark/BenchmarkJava/results/.")
    report = reports[0]
    contexts = parse_findsecbugs_xml(report, rows)
    report_hash = hashlib.sha256(report.read_bytes()).hexdigest()
    for row in rows:
        sid = str(row.get("test_name", row.get("sample_id", "")))
        row["findsecbugs_context"] = contexts.get(sid, "")
        row["sast_context"] = row["findsecbugs_context"]
    print(f"FindSecBugs siap: {report} | konteks {len(rows)}/{len(rows)} sampel | SHA256 {report_hash[:12]}")
    return rows, report_hash


def select_scenario(dataset_path: Path, limit: int | None) -> tuple[dict[str, Any], str, bool]:
    """Present one entry per model + prompt configuration + thinking mode."""
    rows = read_dataset(dataset_path)
    sast_hash = SAST_REPORT_HASH
    if any(s["sast"] == "findsecbugs" for s in SCENARIOS) and not sast_hash:
        rows, sast_hash = ensure_findsecbugs_context(dataset_path)
    if limit is not None:
        if limit < 1:
            raise ValueError("--limit harus >= 1")
        rows = rows[:limit]
    dataset_hash = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    selected_ids = {str(r.get("test_name", r.get("sample_id"))) for r in rows}
    menu: list[tuple[dict[str, Any], str, bool]] = []
    for model in MODELS:
        for scenario in SCENARIOS:
            thinking_modes = (False, True) if model == "gemma4:e4b" else (False,)
            for think in thinking_modes:
                menu.append((scenario, model, think))
    print("\nSkenario:")
    for idx, (scenario, model, think) in enumerate(menu, 1):
        runtime = dict(scenario)
        runtime["think"] = think
        scenario_sast_hash = sast_hash if scenario["sast"] == "findsecbugs" else None
        log_path = output_path(runtime, model, dataset_hash, scenario_sast_hash)
        completed = read_completed(log_path, scenario["id"], model, dataset_hash, scenario_sast_hash) & selected_ids
        label = f"{scenario['id']} ({model} --think={str(think).lower()})"
        print(f"{idx:2}. {label} (completed {len(completed)}/{len(rows)})")
    while True:
        raw = input("Skenario yang akan dijalankan: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(menu):
            return menu[int(raw) - 1]
        # Permit matching a full ID like model__config__think-false.
        matches = []
        for scenario, model, think in menu:
            candidate = f"{model}__{scenario['id']}__think-{str(think).lower()}"
            if raw == candidate:
                matches.append((scenario, model, think))
        if len(matches) == 1:
            return matches[0]
        print("Pilihan tidak valid. Ketik nomor skenario yang ditampilkan.")


def evaluate_pilot(rows: list[dict[str, Any]], records: list[dict[str, Any]]) -> dict[str, Any]:
    truth_by_id = {str(r.get("test_name", r.get("sample_id"))): r for r in rows}
    pred_by_id = {}
    invalid = 0
    errors = 0
    for record in records:
        sid = str(record.get("test_name", ""))
        if sid not in truth_by_id:
            continue
        if record.get("schema_valid") and isinstance(record.get("parsed"), dict): pred_by_id[sid] = record["parsed"]
        elif record.get("success"): invalid += 1
        else: errors += 1
    tp=fp=tn=fn=0; evaluated=0; missing=[]
    for sid, item in truth_by_id.items():
        pred = pred_by_id.get(sid)
        # labels support the existing JSONL schema's real_vulnerability or vulnerable.
        truth = item.get("real_vulnerability", item.get("vulnerable"))
        if not isinstance(truth, bool):
            if isinstance(truth, str) and truth.lower() in {"true","false"}: truth = truth.lower()=="true"
            else: continue
        if not pred: missing.append(sid); continue
        evaluated += 1
        p = pred["vulnerable"]
        if truth and p: tp+=1
        elif not truth and p: fp+=1
        elif truth and not p: fn+=1
        else: tn+=1
    precision=tp/(tp+fp) if tp+fp else 0.0
    recall=tp/(tp+fn) if tp+fn else 0.0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0.0
    acc=(tp+tn)/evaluated if evaluated else 0.0
    return {"dataset_records":len(rows),"predictions_valid":len(pred_by_id),"evaluated":evaluated,"missing_predictions":len(missing),"invalid_responses":invalid,"failed_calls":errors,"tp":tp,"fp":fp,"fn":fn,"tn":tn,"precision":precision,"recall":recall,"f1":f1,"accuracy":acc,"missing_sample_ids":missing[:100]}


def run_scenario(scenario: dict[str, Any], model: str, dataset_path: Path, *, limit: int | None, timeout: int, resume: bool, think_override: bool | None = None) -> int:
    rows = read_dataset(dataset_path)
    sast_hash = SAST_REPORT_HASH
    if scenario["sast"] == "findsecbugs":
        rows, sast_hash = ensure_findsecbugs_context(dataset_path)
    if limit is not None:
        if limit < 1: raise ValueError("--limit harus >= 1")
        rows = rows[:limit]
    dataset_hash = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    think = scenario["think"] if think_override is None else think_override
    scenario_runtime = dict(scenario)
    scenario_runtime["think"] = think
    template, template_name, warning = load_templates(scenario_runtime)
    if warning: print(f"PERINGATAN: {warning}")
    missing_required_sast = scenario["sast"] == "findsecbugs" and any(not str(r.get("findsecbugs_context", r.get("sast_context", ""))).strip() for r in rows)
    if missing_required_sast:
        raise ValueError("Skenario ini membutuhkan hasil FindSecBugs per sampel (findsecbugs_context/sast_context). Hasil scanner tidak tersedia untuk semua sampel; eksekusi dibatalkan.")
    models_available, model_error = load_ollama_models()
    if model_error: raise RuntimeError(f"Ollama tidak dapat dijangkau ({OLLAMA_URL}): {model_error}")
    normalized_model = model if model.endswith(":latest") else model
    aliases = {m.split(":")[0] if ":" in m else m for m in models_available}
    if normalized_model not in models_available and model not in aliases:
        raise RuntimeError(f"Model {model!r} tidak ditemukan di Ollama. Tersedia: {', '.join(sorted(models_available))}")
    outpath = output_path(scenario_runtime, model, dataset_hash, sast_hash)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    completed_all = read_completed(outpath, scenario["id"], model, dataset_hash, sast_hash if scenario["sast"] == "findsecbugs" else None) if resume else set()
    selected_ids = {str(r.get("test_name", r.get("sample_id"))) for r in rows}
    completed = completed_all & selected_ids
    total = len(rows)
    pending = [r for r in rows if str(r.get("test_name", r.get("sample_id"))) not in completed]
    print("\nRingkasan eksekusi")
    print(f"  Skenario : {scenario['id']}")
    print(f"  Model    : {model}")
    print(f"  Thinking : {think}")
    print(f"  Dataset  : {dataset_path} ({total} sampel dipilih)")
    print(f"  Resume   : {len(completed)} selesai; {len(pending)} tersisa")
    print(f"  Prompt   : {template_name}")
    print(f"  Log      : {outpath}")
    confirm = input("Lanjutkan? [Y/n] ").strip().lower()
    if confirm not in {"", "y", "yes"}:
        print("Dibatalkan; tidak ada inferensi dijalankan.")
        return 0
    run_start = time.perf_counter()
    counts = {"valid":0,"invalid":0,"error":0,"skipped":len(completed)}
    # Preserve run config/provenance in each JSONL row.
    with outpath.open("a", encoding="utf-8") as output:
        for index, item in enumerate(rows, 1):
            sid = str(item.get("test_name", item.get("sample_id")))
            if sid in completed:
                print(f"[{index}/{total}] {sid} SKIP (sudah valid dan tersimpan)")
                continue
            try:
                prompt = render_template(template, item, scenario_runtime)
            except Exception as exc:
                record = {"test_name":sid,"scenario_id":scenario["id"],"model":model,"timestamp":utc_now(),"success":False,"elapsed_seconds":0.0,"raw_response":"","parsed":None,"schema_valid":False,"missing_fields":[],"error":f"PROMPT_ERROR: {exc}","dataset_sha256":dataset_hash,"sast_report_sha256":sast_hash if scenario["sast"] == "findsecbugs" else "","prompt_file":template_name,"prompt_sha256":sha256_text(template),"think":think,"sast":scenario["sast"]}
                output.write(json.dumps(record,ensure_ascii=False)+"\n"); output.flush()
                counts["error"]+=1
                print(f"[{index}/{total}] {sid} PROMPT_ERROR: {exc}")
                continue
            options = {"temperature":0.0,"top_p":0.9,"top_k":20,"repeat_penalty":1.0}
            result = call_ollama(model, scenario_runtime["system"], prompt, timeout=timeout, think=think, options=options)
            parsed_raw = parse_json_response(result["response"], scenario["id"]) if result["success"] else None
            resolved_raw, resolver_changes = resolve_prediction(parsed_raw)
            schema_valid, missing_fields, normalized = normalize_prediction(resolved_raw, scenario["id"])
            record = {"test_name":sid,"scenario_id":scenario["id"],"prompt_id":scenario["prompt_id"],"sast":scenario["sast"],"think":think,"model":model,"timestamp":utc_now(),"success":result["success"],"elapsed_seconds":result["elapsed_seconds"],"raw_response":result["response"],"raw_thinking":result["thinking"],"parsed_raw":parsed_raw,"parsed":normalized if normalized is not None else resolved_raw,"resolver_changes":resolver_changes,"schema_valid":schema_valid,"missing_fields":missing_fields,"error":result["error"] if not result["success"] else ("SCHEMA_INVALID" if not schema_valid else None),"dataset_sha256":dataset_hash,"sast_report_sha256":sast_hash if scenario["sast"] == "findsecbugs" else "","prompt_file":template_name,"prompt_sha256":sha256_text(template),"rendered_prompt_sha256":sha256_text(prompt),"options":options}
            # Save every attempt, even API failures and schema-invalid responses.
            output.write(json.dumps(record,ensure_ascii=False)+"\n"); output.flush()
            if not result["success"]: counts["error"]+=1; status="API_ERROR"
            elif not schema_valid: counts["invalid"]+=1; status="SCHEMA_INVALID " + ",".join(missing_fields)
            else: counts["valid"]+=1; status="OK"
            print(f"[{index}/{total}] {sid} {status} {result['elapsed_seconds']:.2f}s")
    # Read this invocation's output records for a summary; metrics omit missing/invalid predictions.
    current_records=[]
    with outpath.open(encoding="utf-8") as f:
        for line in f:
            try:
                rec=json.loads(line)
                if rec.get("dataset_sha256")==dataset_hash and rec.get("scenario_id")==scenario["id"] and rec.get("model")==model:
                    current_records.append(rec)
            except json.JSONDecodeError: pass
    summary=evaluate_pilot(rows,current_records)
    summary.update({"scenario_id":scenario["id"],"model":model,"think":think,"sast":scenario["sast"],"dataset_sha256":dataset_hash,"generated_at_utc":utc_now(),"elapsed_seconds":round(time.perf_counter()-run_start,3),"log_file":str(outpath)})
    summary_path=outpath.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("\n"+"="*60+"\nRINGKASAN PILOT\n"+"="*60)
    print(f"Sampel dataset      : {summary['dataset_records']}")
    print(f"Prediksi valid      : {summary['predictions_valid']}")
    print(f"Dievaluasi          : {summary['evaluated']}")
    print(f"Prediksi hilang     : {summary['missing_predictions']}")
    print(f"Respons invalid     : {summary['invalid_responses']}")
    print(f"Pemanggilan gagal   : {summary['failed_calls']}")
    print(f"TP={summary['tp']} FP={summary['fp']} FN={summary['fn']} TN={summary['tn']}")
    print(f"Precision={summary['precision']:.4f} Recall={summary['recall']:.4f} F1={summary['f1']:.4f} Accuracy={summary['accuracy']:.4f}")
    print(f"Catatan             : {outpath}")
    print(f"Ringkasan JSON      : {summary_path}")
    return 0 if summary["missing_predictions"]==0 and summary["invalid_responses"]==0 and summary["failed_calls"]==0 else 1


def main() -> int:
    import argparse
    parser=argparse.ArgumentParser(description="Interactive scenario runner for OWASP Benchmark Java using Ollama.")
    parser.add_argument("--dataset",type=Path,default=DEFAULT_DATASET,help=f"JSONL dataset (default: {DEFAULT_DATASET})")
    parser.add_argument("--timeout",type=int,default=DEFAULT_TIMEOUT)
    parser.add_argument("--limit",type=int,default=DEFAULT_LIMIT,help="Process only the first N records (e.g. 5 for pilot).")
    parser.add_argument("--scenario",choices=[s["id"] for s in SCENARIOS],help="Select scenario by ID; skips scenario menu.")
    parser.add_argument("--no-resume",action="store_true",help="Do not skip already-valid samples in the output JSONL.")
    parser.add_argument("--model",choices=MODELS,help="Skip model selection prompt.")
    parser.add_argument("--think",choices=["true","false"],help="Override thinking mode for the selected scenario.")
    args=parser.parse_args()
    if args.timeout < 1: parser.error("--timeout harus positif")
    try:
        if args.scenario:
            scenario=next(s for s in SCENARIOS if s["id"]==args.scenario)
            model=args.model or MODELS[0]
            default_think = False
            if model == "gemma4:e4b" and args.think is None:
                default_think = False
            think_override=default_think if args.think is None else args.think=="true"
        else:
            global SAST_REPORT_HASH
            _, SAST_REPORT_HASH = ensure_findsecbugs_context(args.dataset)
            scenario, selected_model, selected_think = select_scenario(args.dataset, args.limit)
            model=args.model or selected_model
            think_override=selected_think if args.think is None else args.think=="true"
        return run_scenario(scenario,model,args.dataset,limit=args.limit,timeout=args.timeout,resume=not args.no_resume,think_override=think_override)
    except (OSError,ValueError,RuntimeError) as exc:
        print(f"\nERROR: {exc}",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
