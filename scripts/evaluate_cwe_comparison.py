#!/usr/bin/env python3

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


GROUND_TRUTH = Path(
    "benchmark/BenchmarkJava/expectedresults-1.2.csv"
)

MODELS = {
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

WIDTH = 100


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def safe_div(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def header(title):
    print()
    print("=" * WIDTH)
    print(title)
    print("=" * WIDTH)
    print()


def normalize_cwe(value):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if value.upper().startswith("CWE-"):
        return value.upper()

    return f"CWE-{value}"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_ground_truth(path):
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
                "vulnerable": (
                    row[2].strip().lower() == "true"
                ),
                "cwe": normalize_cwe(row[3].strip()),
            }

    return results


def parse_llm(path):
    results = {}

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
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
                "cwe": normalize_cwe(
                    parsed.get("cwe")
                ),
            }

    return results


# ---------------------------------------------------------------------------
# Evaluation: deteksi kerentanan (binary)
# ---------------------------------------------------------------------------

def compute_metrics(tp, fp, fn, tn):
    total = tp + fp + fn + tn

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    accuracy = safe_div(tp + tn, total)

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "total": total,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def evaluate_detection(ground_truth, predictions):
    tp = fp = fn = tn = 0
    missing = 0

    per_category = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    )

    for test_name, truth in ground_truth.items():
        predicted = predictions.get(test_name)

        if not predicted:
            missing += 1
            continue

        actual = truth["vulnerable"]
        pred = predicted["vulnerable"]
        category = truth["category"]

        if actual and pred:
            key = "tp"
        elif not actual and pred:
            key = "fp"
        elif actual and not pred:
            key = "fn"
        else:
            key = "tn"

        if key == "tp":
            tp += 1
        elif key == "fp":
            fp += 1
        elif key == "fn":
            fn += 1
        else:
            tn += 1

        per_category[category][key] += 1

    result = compute_metrics(tp, fp, fn, tn)
    result["missing"] = missing
    result["category_metrics"] = {
        category: compute_metrics(**counts)
        for category, counts in per_category.items()
    }

    return result


# ---------------------------------------------------------------------------
# Evaluation: klasifikasi CWE
# ---------------------------------------------------------------------------

def evaluate_cwe(ground_truth, predictions):
    comparable = 0
    correct = 0

    confusion = Counter()

    category_stats = defaultdict(
        lambda: {
            "total": 0,
            "correct": 0,
        }
    )

    for test_name, truth in ground_truth.items():
        predicted = predictions.get(test_name)

        if not predicted:
            continue

        # CWE comparison hanya dilakukan pada
        # test yang memang vulnerable menurut ground truth.
        if not truth["vulnerable"]:
            continue

        actual_cwe = truth["cwe"]
        predicted_cwe = predicted["cwe"]

        # Only vulnerable tests with a valid ground-truth CWE are
        # included in exact CWE classification evaluation.
        # Empty/None model predictions remain comparable and are
        # counted as incorrect.
        if not actual_cwe:
            continue

        comparable += 1

        category = truth["category"]

        category_stats[category]["total"] += 1

        confusion[
            (actual_cwe, predicted_cwe)
        ] += 1

        if (
            predicted_cwe
            and predicted_cwe == actual_cwe
        ):
            correct += 1
            category_stats[category]["correct"] += 1

    return {
        "comparable": comparable,
        "correct": correct,
        "incorrect": comparable - correct,
        "accuracy": safe_div(correct, comparable),
        "confusion": confusion,
        "category_stats": category_stats,
    }


# ---------------------------------------------------------------------------
# Output: deteksi kerentanan
# ---------------------------------------------------------------------------

def print_detection_summary(detection, ground_truth):
    header("VULNERABILITY DETECTION COMPARISON (binary)")

    print(f"Dataset: {len(ground_truth)} tests")
    print("Positive class: vulnerable")
    print()

    print(
        f"{'Model':<16}"
        f"{'TP':>8}"
        f"{'FP':>8}"
        f"{'FN':>8}"
        f"{'TN':>8}"
        f"{'Precision':>12}"
        f"{'Recall':>10}"
        f"{'F1':>10}"
        f"{'Accuracy':>11}"
    )

    print("-" * WIDTH)

    for model, r in detection.items():
        print(
            f"{model:<16}"
            f"{r['tp']:>8}"
            f"{r['fp']:>8}"
            f"{r['fn']:>8}"
            f"{r['tn']:>8}"
            f"{r['precision']:>12.4f}"
            f"{r['recall']:>10.4f}"
            f"{r['f1']:>10.4f}"
            f"{r['accuracy']:>11.4f}"
        )

    print()
    print(
        f"{'Model':<16}"
        f"{'Evaluated':>12}"
        f"{'Missing/Invalid':>18}"
    )
    print("-" * 46)

    for model, r in detection.items():
        print(
            f"{model:<16}"
            f"{r['total']:>12}"
            f"{r['missing']:>18}"
        )

    print()
    print(
        "Catatan: metrik dihitung hanya pada test yang punya prediksi valid. "
        "Positive class = vulnerable."
    )
    print()


def print_detection_by_category(detection):
    header("DETECTION METRICS BY CATEGORY (F1 / Recall / Precision)")

    categories = sorted({
        category
        for r in detection.values()
        for category in r["category_metrics"]
    })

    models = list(detection.keys())

    line = f"{'Category':<18}"
    for model in models:
        line += f"{model:>27}"
    print(line)

    sub = f"{'':<18}"
    for _ in models:
        sub += f"{'F1':>9}{'Rec':>9}{'Prec':>9}"
    print(sub)

    print("-" * WIDTH)

    for category in categories:
        row = f"{category:<18}"

        for model in models:
            m = detection[model]["category_metrics"].get(category)

            if m is None:
                row += f"{'-':>9}{'-':>9}{'-':>9}"
            else:
                row += (
                    f"{m['f1']:>9.4f}"
                    f"{m['recall']:>9.4f}"
                    f"{m['precision']:>9.4f}"
                )

        print(row)


# ---------------------------------------------------------------------------
# Output: klasifikasi CWE
# ---------------------------------------------------------------------------

def print_cwe_summary(cwe_results):
    header("CWE CLASSIFICATION COMPARISON")

    print("Dataset: vulnerable tests with valid ground-truth CWE")
    print("Metric: exact CWE match")
    print("None/empty CWE predictions count as incorrect")
    print()

    print(
        f"{'Model':<18}"
        f"{'Comparable':>12}"
        f"{'Correct':>10}"
        f"{'Incorrect':>12}"
        f"{'Accuracy':>12}"
    )

    print("-" * WIDTH)

    for model, result in cwe_results.items():
        print(
            f"{model:<18}"
            f"{result['comparable']:>12}"
            f"{result['correct']:>10}"
            f"{result['incorrect']:>12}"
            f"{result['accuracy']:>12.4f}"
        )


def print_cwe_category_comparison(cwe_results):
    header("CWE ACCURACY BY CATEGORY (correct/total  accuracy)")

    print("Denominator: vulnerable tests in each category")
    print()

    categories = sorted({
        category
        for result in cwe_results.values()
        for category in result["category_stats"]
    })

    models = list(cwe_results.keys())

    line = f"{'Category':<18}"
    for model in models:
        line += f"{model:>27}"
    print(line)

    print("-" * WIDTH)

    for category in categories:
        row = f"{category:<18}"

        for model in models:
            stats = cwe_results[model]["category_stats"].get(category)

            if not stats or not stats["total"]:
                row += f"{'-':>27}"
                continue

            acc = safe_div(stats["correct"], stats["total"])
            cell = f"{stats['correct']}/{stats['total']}  {acc:.4f}"
            row += f"{cell:>27}"

        print(row)


def print_top_confusions(cwe_results, limit=20):
    for model, result in cwe_results.items():
        header(f"TOP CWE CONFUSIONS — {model}")

        rows = sorted(
            result["confusion"].items(),
            key=lambda item: item[1],
            reverse=True,
        )

        shown = 0

        for (actual, predicted), count in rows:
            if actual == predicted:
                continue

            print(
                f"{actual:10} -> "
                f"{str(predicted):10} : {count}"
            )

            shown += 1

            if shown >= limit:
                break


def print_correct_predictions(cwe_results, limit=20):
    for model, result in cwe_results.items():
        header(f"TOP CORRECT CWE PREDICTIONS — {model}")

        rows = sorted(
            (
                (actual, predicted, count)
                for (actual, predicted), count
                in result["confusion"].items()
                if actual == predicted
            ),
            key=lambda item: item[2],
            reverse=True,
        )

        for actual, predicted, count in rows[:limit]:
            print(
                f"✓ {actual:10} -> "
                f"{predicted:10} : {count}"
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ground_truth = parse_ground_truth(GROUND_TRUTH)

    print(f"Ground truth tests: {len(ground_truth)}")

    detection_results = {}
    cwe_results = {}

    for model, path in MODELS.items():
        predictions = parse_llm(path)

        print(f"{model} predictions: {len(predictions)}")

        detection_results[model] = evaluate_detection(
            ground_truth,
            predictions,
        )

        cwe_results[model] = evaluate_cwe(
            ground_truth,
            predictions,
        )

    # Deteksi kerentanan
    print_detection_summary(detection_results, ground_truth)
    print_detection_by_category(detection_results)

    # Klasifikasi CWE
    print_cwe_summary(cwe_results)
    print_cwe_category_comparison(cwe_results)
    print_top_confusions(cwe_results)
    print_correct_predictions(cwe_results)


if __name__ == "__main__":
    main()