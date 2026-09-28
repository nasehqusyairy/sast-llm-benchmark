#!/usr/bin/env python3

import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


TEST_PATTERN = re.compile(r"BenchmarkTest\d+")


def parse_ground_truth(path: Path):
    """
    Parse OWASP Benchmark expectedresults CSV.

    Format:
        test_name,category,real_vulnerability,cwe
    """
    results = {}

    with path.open("r", encoding="utf-8") as f:
        reader = csv.reader(
            line for line in f
            if not line.startswith("#")
        )

        for row in reader:
            if len(row) < 4:
                continue

            test_name = row[0].strip()
            category = row[1].strip()
            real_vulnerability = row[2].strip().lower() == "true"
            cwe = row[3].strip()

            results[test_name] = {
                "category": category,
                "real_vulnerability": real_vulnerability,
                "cwe": cwe,
            }

    return results


def extract_test_name(bug):
    """
    Extract BenchmarkTestXXXXX from a BugInstance.

    We inspect the serialized BugInstance because the test name
    can occur in several XML attributes.
    """
    text = ET.tostring(bug, encoding="unicode")

    match = TEST_PATTERN.search(text)

    if match:
        return match.group(0)

    return None


def parse_sast_xml(path: Path):
    """
    Parse a SpotBugs/FindSecBugs XML result.

    Returns:
        {
            test_name: {
                "finding_count": int,
                "types": set[str],
            }
        }
    """
    root = ET.parse(path).getroot()

    results = {}

    for bug in root.findall(".//BugInstance"):
        test_name = extract_test_name(bug)

        if not test_name:
            continue

        bug_type = bug.get("type", "UNKNOWN")

        if test_name not in results:
            results[test_name] = {
                "finding_count": 0,
                "types": set(),
            }

        results[test_name]["finding_count"] += 1
        results[test_name]["types"].add(bug_type)

    return results


def evaluate_detection(ground_truth, findings):
    """
    Test-level binary evaluation.

    Positive prediction:
        The SAST tool produced >= 1 finding for the BenchmarkTest.

    Ground truth:
        expectedresults-1.2.csv
    """
    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for test_name, truth in ground_truth.items():
        actual = truth["real_vulnerability"]
        predicted = test_name in findings

        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and not predicted:
            tn += 1

    total = tp + fp + fn + tn

    precision = (
        tp / (tp + fp)
        if tp + fp > 0
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn > 0
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall > 0
        else 0.0
    )

    accuracy = (
        (tp + tn) / total
        if total > 0
        else 0.0
    )

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "total": total,
    }


def build_rows(ground_truth, tool_findings):
    """
    Build a unified per-test CSV representation.
    """
    rows = []

    for test_name, truth in sorted(ground_truth.items()):
        finding = tool_findings.get(test_name)

        rows.append({
            "test_name": test_name,
            "category": truth["category"],
            "real_vulnerability": str(
                truth["real_vulnerability"]
            ).lower(),
            "cwe": truth["cwe"],
            "detected": str(
                finding is not None
            ).lower(),
            "finding_count": (
                finding["finding_count"]
                if finding
                else 0
            ),
            "finding_types": (
                ";".join(sorted(finding["types"]))
                if finding
                else ""
            ),
        })

    return rows


def write_csv(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "test_name",
        "category",
        "real_vulnerability",
        "cwe",
        "detected",
        "finding_count",
        "finding_types",
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False,
        )


def print_summary(name, findings, metrics):
    print()
    print("=" * 60)
    print(name)
    print("=" * 60)

    print(f"Detected BenchmarkTests : {len(findings)}")
    print(f"TP                      : {metrics['tp']}")
    print(f"FP                      : {metrics['fp']}")
    print(f"FN                      : {metrics['fn']}")
    print(f"TN                      : {metrics['tn']}")
    print(f"Precision               : {metrics['precision']:.4f}")
    print(f"Recall                  : {metrics['recall']:.4f}")
    print(f"F1                      : {metrics['f1']:.4f}")
    print(f"Accuracy                : {metrics['accuracy']:.4f}")


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate SpotBugs/FindSecBugs on OWASP Benchmark Java."
    )

    parser.add_argument(
        "--ground-truth",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--spotbugs",
        type=Path,
    )

    parser.add_argument(
        "--findsecbugs",
        type=Path,
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output directory.",
    )

    args = parser.parse_args()

    if not args.spotbugs and not args.findsecbugs:
        parser.error(
            "At least one of --spotbugs or --findsecbugs is required."
        )

    ground_truth = parse_ground_truth(
        args.ground_truth
    )

    print(f"Ground truth tests : {len(ground_truth)}")

    output_dir = args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "benchmark": {
            "ground_truth_tests": len(ground_truth),
        },
        "tools": {},
    }

    tools = []

    if args.spotbugs:
        tools.append(
            (
                "spotbugs",
                args.spotbugs,
            )
        )

    if args.findsecbugs:
        tools.append(
            (
                "findsecbugs",
                args.findsecbugs,
            )
        )

    for tool_name, xml_path in tools:
        print()
        print(f"Parsing {tool_name}: {xml_path}")

        findings = parse_sast_xml(xml_path)

        metrics = evaluate_detection(
            ground_truth,
            findings,
        )

        rows = build_rows(
            ground_truth,
            findings,
        )

        csv_path = (
            output_dir
            / f"{tool_name}-per-test.csv"
        )

        write_csv(
            csv_path,
            rows,
        )

        summary["tools"][tool_name] = {
            "input": str(xml_path),
            "detected_tests": len(findings),
            "metrics": metrics,
        }

        print_summary(
            tool_name,
            findings,
            metrics,
        )

        print(f"CSV: {csv_path}")

    summary_path = (
        output_dir
        / "summary.json"
    )

    write_json(
        summary_path,
        summary,
    )

    print()
    print(f"Summary: {summary_path}")


if __name__ == "__main__":
    main()