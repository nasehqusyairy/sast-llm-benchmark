#!/usr/bin/env python3

import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path


TEST_PATTERN = re.compile(r"BenchmarkTest\d+")

SECURITY_CATEGORIES = {
    "SECURITY",
    "MALICIOUS_CODE",
}


def parse_ground_truth(path: Path):
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

            results[test_name] = {
                "category": row[1].strip(),
                "real_vulnerability": (
                    row[2].strip().lower() == "true"
                ),
                "cwe": row[3].strip(),
            }

    return results


def parse_sast_security_xml(path: Path):
    """
    Extract only security-related findings from
    SpotBugs/FindSecBugs XML.

    A test is considered detected if it has at least
    one BugInstance whose category is SECURITY or
    MALICIOUS_CODE.
    """

    root = ET.parse(path).getroot()

    findings = {}

    for bug in root.findall(".//BugInstance"):
        category = bug.get("category", "")

        if category not in SECURITY_CATEGORIES:
            continue

        text = ET.tostring(
            bug,
            encoding="unicode",
        )

        match = TEST_PATTERN.search(text)

        if not match:
            continue

        test_name = match.group(0)
        bug_type = bug.get("type", "UNKNOWN")

        if test_name not in findings:
            findings[test_name] = {
                "finding_count": 0,
                "finding_types": set(),
            }

        findings[test_name]["finding_count"] += 1
        findings[test_name]["finding_types"].add(
            bug_type
        )

    return findings


def evaluate(ground_truth, findings):
    tp = fp = fn = tn = 0

    for test_name, truth in ground_truth.items():
        actual = truth["real_vulnerability"]
        predicted = test_name in findings

        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif actual and not predicted:
            fn += 1
        else:
            tn += 1

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
        (tp + tn) /
        (tp + fp + fn + tn)
        if tp + fp + fn + tn > 0
        else 0.0
    )

    fpr = (
        fp / (fp + tn)
        if fp + tn > 0
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
        "false_positive_rate": fpr,
    }


def build_rows(ground_truth, findings):
    rows = []

    for test_name, truth in sorted(ground_truth.items()):
        finding = findings.get(test_name)

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
                ";".join(
                    sorted(finding["finding_types"])
                )
                if finding
                else ""
            ),
        })

    return rows


def write_csv(path: Path, rows):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "test_name",
        "category",
        "real_vulnerability",
        "cwe",
        "detected",
        "finding_count",
        "finding_types",
    ]

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate security findings from "
            "SpotBugs/FindSecBugs against OWASP Benchmark Java."
        )
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
    )

    args = parser.parse_args()

    if not args.spotbugs and not args.findsecbugs:
        parser.error(
            "At least one SAST report is required."
        )

    ground_truth = parse_ground_truth(
        args.ground_truth
    )

    args.output.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary = {
        "benchmark": {
            "ground_truth_tests": len(ground_truth),
            "positive_tests": sum(
                1
                for x in ground_truth.values()
                if x["real_vulnerability"]
            ),
            "negative_tests": sum(
                1
                for x in ground_truth.values()
                if not x["real_vulnerability"]
            ),
        },
        "tools": {},
    }

    tools = []

    if args.spotbugs:
        tools.append(
            ("spotbugs", args.spotbugs)
        )

    if args.findsecbugs:
        tools.append(
            ("findsecbugs", args.findsecbugs)
        )

    for tool_name, xml_path in tools:
        print()
        print("=" * 60)
        print(tool_name.upper())
        print("=" * 60)

        findings = parse_sast_security_xml(
            xml_path
        )

        metrics = evaluate(
            ground_truth,
            findings,
        )

        rows = build_rows(
            ground_truth,
            findings,
        )

        csv_path = (
            args.output
            / f"{tool_name}-security-per-test.csv"
        )

        write_csv(
            csv_path,
            rows,
        )

        summary["tools"][tool_name] = {
            "input": str(xml_path),
            "security_detected_tests": len(
                findings
            ),
            "metrics": metrics,
        }

        print(
            f"Security detected tests : "
            f"{len(findings)}"
        )

        print(
            f"TP                     : "
            f"{metrics['tp']}"
        )
        print(
            f"FP                     : "
            f"{metrics['fp']}"
        )
        print(
            f"FN                     : "
            f"{metrics['fn']}"
        )
        print(
            f"TN                     : "
            f"{metrics['tn']}"
        )

        print(
            f"Precision              : "
            f"{metrics['precision']:.4f}"
        )
        print(
            f"Recall                 : "
            f"{metrics['recall']:.4f}"
        )
        print(
            f"F1                     : "
            f"{metrics['f1']:.4f}"
        )
        print(
            f"Accuracy               : "
            f"{metrics['accuracy']:.4f}"
        )
        print(
            f"False Positive Rate    : "
            f"{metrics['false_positive_rate']:.4f}"
        )

        print(f"CSV: {csv_path}")

    summary_path = (
        args.output / "summary.json"
    )

    with summary_path.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            summary,
            f,
            indent=2,
        )

    print()
    print(f"Summary: {summary_path}")


if __name__ == "__main__":
    main()
