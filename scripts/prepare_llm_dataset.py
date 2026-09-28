#!/usr/bin/env python3

import argparse
import csv
import json
from pathlib import Path


def load_ground_truth(path: Path):
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


def load_source_files(source_dir: Path):
    sources = {}

    for path in source_dir.glob("BenchmarkTest*.java"):
        sources[path.stem] = path

    return sources


def build_dataset(ground_truth, source_files):
    dataset = []

    missing_source = []

    for test_name in sorted(ground_truth):
        source_path = source_files.get(test_name)

        if source_path is None:
            missing_source.append(test_name)
            continue

        code = source_path.read_text(
            encoding="utf-8"
        )

        truth = ground_truth[test_name]

        dataset.append({
            "test_name": test_name,
            "code": code,
            "category": truth["category"],
            "cwe": truth["cwe"],
            "real_vulnerability": truth[
                "real_vulnerability"
            ],
        })

    return dataset, missing_source


def write_jsonl(path: Path, dataset):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as f:
        for record in dataset:
            f.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Prepare OWASP Benchmark Java "
            "dataset for standalone LLM evaluation."
        )
    )

    parser.add_argument(
        "--ground-truth",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--source-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    ground_truth = load_ground_truth(
        args.ground_truth
    )

    source_files = load_source_files(
        args.source_dir
    )

    print(
        f"Ground truth records : "
        f"{len(ground_truth)}"
    )

    print(
        f"Source files         : "
        f"{len(source_files)}"
    )

    dataset, missing = build_dataset(
        ground_truth,
        source_files,
    )

    write_jsonl(
        args.output,
        dataset,
    )

    print(
        f"Dataset records      : "
        f"{len(dataset)}"
    )

    print(
        f"Missing source files : "
        f"{len(missing)}"
    )

    if missing:
        print("\nMissing:")
        for name in missing[:20]:
            print(f"  {name}")

        if len(missing) > 20:
            print(
                f"  ... and "
                f"{len(missing) - 20} more"
            )


if __name__ == "__main__":
    main()