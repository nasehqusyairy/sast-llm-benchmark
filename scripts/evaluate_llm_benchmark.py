#!/usr/bin/env python3

import argparse
import csv
import json
from pathlib import Path


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


def parse_llm_jsonl(path: Path):
    results = {}

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                print(
                    f"WARNING: Invalid JSON at line {line_number}: {e}"
                )
                continue

            test_name = record.get("test_name")
            parsed = record.get("parsed")

            if not test_name:
                continue

            if not isinstance(parsed, dict):
                continue

            vulnerable = parsed.get("vulnerable")

            if not isinstance(vulnerable, bool):
                continue

            results[test_name] = {
                "vulnerable": vulnerable,
                "cwe": parsed.get("cwe"),
                "line": parsed.get("line"),
                "reason": parsed.get("reason"),
            }

    return results


def evaluate(ground_truth, predictions):
    tp = fp = fn = tn = 0

    for test_name, truth in ground_truth.items():
        actual = truth["real_vulnerability"]
        predicted_record = predictions.get(test_name)

        predicted = (
            predicted_record["vulnerable"]
            if predicted_record
            else False
        )

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
        (tp + tn) / (tp + fp + fn + tn)
        if tp + fp + fn + tn > 0
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
    }


def build_rows(ground_truth, predictions):
    rows = []

    for test_name, truth in sorted(ground_truth.items()):
        prediction = predictions.get(test_name)

        predicted = (
            prediction["vulnerable"]
            if prediction
            else False
        )

        rows.append({
            "test_name": test_name,
            "category": truth["category"],
            "real_vulnerability": str(
                truth["real_vulnerability"]
            ).lower(),
            "cwe": truth["cwe"],
            "predicted_vulnerable": str(
                predicted
            ).lower(),
            "predicted_cwe": (
                prediction["cwe"]
                if prediction and prediction["cwe"]
                else ""
            ),
            "predicted_line": (
                prediction["line"]
                if prediction and prediction["line"] is not None
                else ""
            ),
            "reason": (
                prediction["reason"]
                if prediction and prediction["reason"]
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
        "predicted_vulnerable",
        "predicted_cwe",
        "predicted_line",
        "reason",
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
        description="Evaluate standalone LLM on OWASP Benchmark Java."
    )

    parser.add_argument(
        "--ground-truth",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--llm",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--model",
        required=True,
        help="Model name used to identify evaluation outputs.",
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    ground_truth = parse_ground_truth(
        args.ground_truth
    )

    predictions = parse_llm_jsonl(
        args.llm
    )

    metrics = evaluate(
        ground_truth,
        predictions,
    )

    rows = build_rows(
        ground_truth,
        predictions,
    )

    args.output.mkdir(
        parents=True,
        exist_ok=True,
    )

    safe_model = "".join(
        c if c.isalnum() or c in "._-" else "-"
        for c in args.model
    )

    csv_path = (
        args.output
        / f"{safe_model}-per-test.csv"
    )

    summary_path = (
        args.output
        / f"{safe_model}-summary.json"
    )

    write_csv(
        csv_path,
        rows,
    )

    summary = {
        "model": args.model,
        "benchmark": {
            "ground_truth_tests": len(ground_truth),
            "llm_predictions": len(predictions),
            "missing_predictions": (
                len(ground_truth) - len(predictions)
            ),
        },
        "metrics": metrics,
    }

    with summary_path.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            summary,
            f,
            indent=2,
        )

    print("=" * 60)
    print("LLM EVALUATION")
    print("=" * 60)

    print(f"Model              : {args.model}")
    print(f"Ground truth tests : {len(ground_truth)}")
    print(f"LLM predictions    : {len(predictions)}")
    print(
        f"Missing predictions: "
        f"{len(ground_truth) - len(predictions)}"
    )

    print()
    print(f"TP        : {metrics['tp']}")
    print(f"FP        : {metrics['fp']}")
    print(f"FN        : {metrics['fn']}")
    print(f"TN        : {metrics['tn']}")
    print(f"Precision : {metrics['precision']:.4f}")
    print(f"Recall    : {metrics['recall']:.4f}")
    print(f"F1        : {metrics['f1']:.4f}")
    print(f"Accuracy  : {metrics['accuracy']:.4f}")

    print()
    print(f"CSV     : {csv_path}")
    print(f"Summary : {summary_path}")


if __name__ == "__main__":
    main()
