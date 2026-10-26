import io
import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import run_llm_benchmark3 as runner


class RunLlmBenchmark3Tests(unittest.TestCase):
    def write_inputs(self, directory: Path) -> tuple[Path, Path]:
        dataset = directory / "dataset.jsonl"
        dataset.write_text(
            json.dumps(
                {
                    "test_name": "BenchmarkTest00001",
                    "code": "class Sample { void run() {} }",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        ground_truth = directory / "ground-truth.csv"
        ground_truth.write_text(
            "# test name, category, real vulnerability, cwe\n"
            "BenchmarkTest00001, pathtraver, true, 22\n",
            encoding="utf-8",
        )
        return dataset, ground_truth

    def test_missing_explicit_ground_truth_does_not_fall_back_to_default(self) -> None:
        missing_path = Path("/definitely/missing/ground-truth.csv")

        with self.assertRaisesRegex(FileNotFoundError, "tidak ditemukan"):
            runner.find_ground_truth_path(missing_path)

    def test_false_negative_does_not_receive_cwe_or_category_credit(self) -> None:
        rows = [
            {
                "test_name": "BenchmarkTest00001",
                "ground_truth": {
                    "vulnerable": True,
                    "category": "pathtraver",
                    "cwe": "CWE-22",
                },
            }
        ]
        records = [
            {
                "test_name": "BenchmarkTest00001",
                "schema_valid": True,
                "parsed": {
                    "vulnerable": False,
                    "cwe": "CWE-22",
                    "line": 1,
                    "reason": "Not vulnerable",
                },
            }
        ]

        with patch.object(runner, "CWE_CATEGORY_MAP", {"pathtraver": 22}):
            summary = runner.evaluate_pilot(rows, records)

        self.assertEqual(summary["fn"], 1)
        self.assertEqual(summary["cwe_correct"], 0)
        self.assertEqual(summary["category_correct"], 0)
        self.assertFalse(summary["row_comparisons"][0]["category_correct"])

    def test_latest_attempt_supersedes_an_older_valid_prediction(self) -> None:
        rows = [
            {
                "test_name": "BenchmarkTest00001",
                "ground_truth": {"vulnerable": False, "category": "pathtraver", "cwe": "CWE-22"},
            }
        ]
        records = [
            {
                "test_name": "BenchmarkTest00001",
                "success": True,
                "schema_valid": True,
                "parsed": {"vulnerable": False, "cwe": "", "line": None, "reason": ""},
            },
            {
                "test_name": "BenchmarkTest00001",
                "success": False,
                "schema_valid": False,
                "parsed": None,
            },
        ]

        summary = runner.evaluate_pilot(rows, records)

        self.assertEqual(summary["predictions_valid"], 0)
        self.assertEqual(summary["missing_predictions"], 1)
        self.assertEqual(summary["failed_calls"], 1)

    def test_run_scenario_uses_custom_ground_truth_and_records_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            dataset, ground_truth = self.write_inputs(directory)
            output_dir = directory / "output"
            scenario = {
                "id": "baseline-1",
                "label": "baseline-1",
                "prompt_id": "baseline-1",
                "sast": "none",
                "think": False,
                "template": "unused.txt",
                "system": "Analyze the code.",
            }
            ollama_response = {
                "success": True,
                "response": json.dumps(
                    {
                        "vulnerable": True,
                        "cwe": "CWE-22",
                        "line": 1,
                        "reason": "Untrusted path",
                    }
                ),
                "thinking": "",
                "elapsed_seconds": 0.01,
                "error": None,
            }

            with (
                patch.object(runner, "OUTPUT_DIR", output_dir),
                patch.object(runner, "load_ollama_models", return_value=({"model:1"}, None)),
                patch.object(
                    runner,
                    "load_templates",
                    return_value=("source: {JAVA_SOURCE_CODE}", "test-template", None),
                ),
                patch.object(runner, "call_ollama", return_value=ollama_response),
                patch("builtins.input", return_value="y"),
            ):
                exit_code = runner.run_scenario(
                    scenario,
                    "model:1",
                    dataset,
                    limit=None,
                    timeout=5,
                    resume=False,
                    ground_truth_path=ground_truth,
                )

            self.assertEqual(exit_code, 0)
            output_file = next(output_dir.glob("*.jsonl"))
            record = json.loads(output_file.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(record["ground_truth_file"], str(ground_truth.resolve()))
            self.assertEqual(
                record["ground_truth_sha256"],
                hashlib.sha256(ground_truth.read_bytes()).hexdigest(),
            )
            self.assertEqual(record["ground_truth"]["cwe"], "CWE-22")
            summary = json.loads(output_file.with_suffix(".summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["evaluated"], 1)

    def test_selecting_menu_does_not_run_findsecbugs_preemptively(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            dataset, ground_truth = self.write_inputs(Path(temporary_directory))
            scenarios = [
                {
                    "id": "baseline-1",
                    "sast": "none",
                    "think": False,
                },
                {
                    "id": "baseline-2",
                    "sast": "findsecbugs",
                    "think": False,
                },
            ]
            with (
                patch.object(runner, "SCENARIOS", scenarios),
                patch.object(runner, "MODELS", ["model:1"]),
                patch.object(runner, "OUTPUT_DIR", Path(temporary_directory) / "output"),
                patch.object(runner, "ensure_findsecbugs_context") as scanner,
                patch("builtins.input", return_value="1"),
            ):
                selected, selected_model, _ = runner.select_scenario(
                    dataset,
                    None,
                    ground_truth_path=ground_truth,
                )

            self.assertEqual(selected["id"], "baseline-1")
            self.assertEqual(selected_model, "model:1")
            scanner.assert_not_called()

    def test_scenario_menu_uses_the_model_for_each_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            dataset, ground_truth = self.write_inputs(Path(temporary_directory))
            output = io.StringIO()
            with (
                patch.object(runner, "SCENARIOS", [{"id": "baseline-1", "sast": "none", "think": False}]),
                patch.object(runner, "MODELS", ["model:1", "model:2"]),
                patch.object(runner, "OUTPUT_DIR", Path(temporary_directory) / "output"),
                patch("builtins.input", return_value="2"),
                redirect_stdout(output),
            ):
                _, selected_model, _ = runner.select_scenario(
                    dataset,
                    None,
                    ground_truth_path=ground_truth,
                )

            self.assertEqual(selected_model, "model:2")
            self.assertIn("baseline-1 (model:1 --think=false)", output.getvalue())
            self.assertIn("baseline-1 (model:2 --think=false)", output.getvalue())

    def test_findsecbugs_sample_id_matching_is_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            report = Path(temporary_directory) / "findsecbugs.xml"
            report.write_text(
                "<BugCollection><BugInstance type='RULE' category='SECURITY'>"
                "<SourceLine start='3'><Message>benchmarktest00001</Message>"
                "</SourceLine></BugInstance></BugCollection>",
                encoding="utf-8",
            )

            contexts = runner.parse_findsecbugs_xml(
                report,
                [{"test_name": "BenchmarkTest00001"}],
            )

            self.assertIn("rule=RULE", contexts["BenchmarkTest00001"])


if __name__ == "__main__":
    unittest.main()
