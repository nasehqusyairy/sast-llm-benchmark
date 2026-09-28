#!/usr/bin/env python3

import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path


TEST_PATTERN = re.compile(r"BenchmarkTest\d+")


GROUND_TRUTH = Path(
    "benchmark/BenchmarkJava/expectedresults-1.2.csv"
)

SPOTBUGS = Path(
    "benchmark/BenchmarkJava/results/"
    "Benchmark_1.2-spotbugs-v4.10.4-257.xml"
)

FINDSECBUGS = Path(
    "benchmark/BenchmarkJava/results/"
    "Benchmark_1.2-findsecbugs-v1.14.0-73.xml"
)

LLMS = {
    "Qwen2.5-3B": Path(
        "results/llm/raw/qwen2.5-3b.jsonl"
    ),
    "Gemma4-E4B": Path(
        "results/llm/raw/gemma4-e4b.jsonl"
    ),
    "Qwen3-8B": Path(
        "results/llm/raw/qwen3-8b.jsonl"
    ),
}


def parse_ground_truth():
    results = {}

    with GROUND_TRUTH.open(
        "r",
        encoding="utf-8",
    ) as f:
        reader = csv.reader(
            line for line in f
            if not line.startswith("#")
        )

        for row in reader:
            if len(row) < 4:
                continue

            results[row[0].strip()] = {
                "category": row[1].strip(),
                "vulnerable": (
                    row[2].strip().lower()
                    == "true"
                ),
                "cwe": row[3].strip(),
            }

    return results


def parse_sast(path):
    root = ET.parse(path).getroot()

    findings = set()

    for bug in root.findall(".//BugInstance"):
        category = bug.get("category", "")

        if category not in {
            "SECURITY",
            "MALICIOUS_CODE",
        }:
            continue

        text = ET.tostring(
            bug,
            encoding="unicode",
        )

        match = TEST_PATTERN.search(text)

        if match:
            findings.add(match.group(0))

    return findings


def parse_llm(path):
    predictions = {}

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:
        for line in f:
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            test_name = record.get("test_name")
            parsed = record.get("parsed")

            if (
                test_name
                and isinstance(parsed, dict)
                and isinstance(
                    parsed.get("vulnerable"),
                    bool,
                )
            ):
                predictions[test_name] = (
                    parsed["vulnerable"]
                )

    return predictions


def calculate(ground_truth, predictions):
    grouped = defaultdict(
        lambda: {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "tn": 0,
        }
    )

    for test_name, truth in ground_truth.items():
        category = truth["category"]
        actual = truth["vulnerable"]

        if isinstance(predictions, set):
            predicted = test_name in predictions
        else:
            # Prediksi yang hilang/gagal di-parse
            # dianggap "tidak vulnerable".
            predicted = predictions.get(
                test_name,
                False,
            )

        if actual and predicted:
            grouped[category]["tp"] += 1
        elif not actual and predicted:
            grouped[category]["fp"] += 1
        elif actual and not predicted:
            grouped[category]["fn"] += 1
        else:
            grouped[category]["tn"] += 1

    return grouped


def metrics(values):
    tp = values["tp"]
    fp = values["fp"]
    fn = values["fn"]
    tn = values["tn"]

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn
        else 0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if precision + recall
        else 0
    )

    fpr = (
        fp / (fp + tn)
        if fp + tn
        else 0
    )

    return {
        **values,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def main():
    ground_truth = parse_ground_truth()

    tools = {
        "SpotBugs": parse_sast(SPOTBUGS),
        "FindSecBugs": parse_sast(FINDSECBUGS),
    }

    for model_name, path in LLMS.items():
        tools[model_name] = parse_llm(path)

    grouped_results = {}

    for tool_name, predictions in tools.items():
        grouped = calculate(
            ground_truth,
            predictions,
        )

        grouped_results[tool_name] = {
            category: metrics(values)
            for category, values
            in grouped.items()
        }

    categories = sorted(
        {
            truth["category"]
            for truth in ground_truth.values()
        }
    )

    print()
    print("=" * 100)
    print("CATEGORY-LEVEL SECURITY EVALUATION")
    print("=" * 100)

    for category in categories:
        vulnerable_count = sum(
            1
            for truth in ground_truth.values()
            if (
                truth["category"] == category
                and truth["vulnerable"]
            )
        )

        print()
        print(
            f"{category.upper()} "
            f"(vulnerable={vulnerable_count})"
        )

        print(
            f"{'Tool':<15}"
            f"{'TP':>6}"
            f"{'FP':>6}"
            f"{'FN':>6}"
            f"{'TN':>6}"
            f"{'Precision':>12}"
            f"{'Recall':>10}"
            f"{'F1':>10}"
            f"{'FPR':>10}"
        )

        print("-" * 100)

        for tool_name in tools:
            result = grouped_results[
                tool_name
            ][category]

            print(
                f"{tool_name:<15}"
                f"{result['tp']:>6}"
                f"{result['fp']:>6}"
                f"{result['fn']:>6}"
                f"{result['tn']:>6}"
                f"{result['precision']:>12.4f}"
                f"{result['recall']:>10.4f}"
                f"{result['f1']:>10.4f}"
                f"{result['fpr']:>10.4f}"
            )

    output = Path(
        "results/comparison/category-level.json"
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            grouped_results,
            f,
            indent=2,
        )

    print()
    print(f"JSON: {output}")


if __name__ == "__main__":
    main()