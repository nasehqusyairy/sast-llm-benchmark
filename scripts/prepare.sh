#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WITH_SAST=0

usage() {
    cat <<'EOF'
Usage: ./scripts/prepare.sh [--with-sast]

Prepare the checked-in LLM dataset and prompt files.
--with-sast also clones/builds OWASP Benchmark and runs FindSecBugs.
EOF
}

for arg in "$@"; do
    case "$arg" in
        --with-sast) WITH_SAST=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Argumen tidak dikenal: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: Python 3.10+ belum terpasang." >&2
    exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    echo "ERROR: Diperlukan Python 3.10 atau lebih baru." >&2
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    echo "ERROR: Git diperlukan untuk menyiapkan OWASP Benchmark." >&2
    exit 1
fi

if [[ ! -s llm/dataset.jsonl ]]; then
    echo "ERROR: Dataset tidak ditemukan atau kosong: $ROOT_DIR/llm/dataset.jsonl" >&2
    exit 1
fi

for prompt in \
    prompts/baseline_1.txt \
    prompts/baseline_2.txt \
    prompts/zero_shot.txt \
    prompts/cot.txt \
    prompts/tot.txt \
    prompts/munson_adaptations/zero_shot_none_v1.txt \
    prompts/munson_adaptations/zero_shot_findsecbugs_v1.txt \
    prompts/munson_adaptations/cot_none_v1.txt \
    prompts/munson_adaptations/cot_findsecbugs_v1.txt \
    prompts/munson_adaptations/tot_none_v2.txt \
    prompts/munson_adaptations/tot_findsecbugs_v2.txt
do
    if [[ ! -s "$prompt" ]]; then
        echo "ERROR: Prompt tidak ditemukan atau kosong: $ROOT_DIR/$prompt" >&2
        exit 1
    fi
done

python3 scripts/run_llm_benchmark3.py --help >/dev/null
echo "Dataset, prompt, dan runner siap."
echo "Dependensi Python tambahan tidak diperlukan (runner menggunakan standard library)."

benchmark_dir="benchmark/BenchmarkJava"
utils_dir="benchmark/BenchmarkUtils"

if [[ ! -d "$benchmark_dir" ]]; then
    mkdir -p benchmark
    echo "Mengunduh OWASP BenchmarkJava ke $benchmark_dir..."
    git clone --depth 1 \
        https://github.com/nasehqusyairy/BenchmarkJava.git \
        "$benchmark_dir"
fi

if [[ ! -s "$benchmark_dir/expectedresults-1.2.csv" ||
      ! -x "$benchmark_dir/scripts/runFindSecBugs.sh" ]]; then
    echo "ERROR: $benchmark_dir tidak memiliki expectedresults-1.2.csv atau scripts/runFindSecBugs.sh." >&2
    echo "Pastikan folder tersebut berisi checkout BenchmarkJava v1.2 yang benar; skrip tidak mengubah atau menimpanya." >&2
    exit 1
fi

echo "OWASP BenchmarkJava siap di $ROOT_DIR/$benchmark_dir."

if (( ! WITH_SAST )); then
    echo "Untuk menyiapkan plugin dan menjalankan FindSecBugs, gunakan ./scripts/prepare.sh --with-sast."
    exit 0
fi

for tool in mvn java; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: Perintah '$tool' diperlukan untuk persiapan FindSecBugs." >&2
        exit 1
    fi
done

if [[ ! -d "$utils_dir" ]]; then
    echo "Mengunduh OWASP BenchmarkUtils ke $utils_dir..."
    git clone --depth 1 \
        https://github.com/OWASP-Benchmark/BenchmarkUtils.git \
        "$utils_dir"
fi

if [[ ! -s "$utils_dir/pom.xml" ]]; then
    echo "ERROR: pom.xml tidak ditemukan di $utils_dir." >&2
    exit 1
fi

echo "Menginstal OWASP BenchmarkUtils ke Maven lokal..."
mvn -f "$utils_dir/pom.xml" install

echo "Menjalankan FindSecBugs (dapat memerlukan waktu beberapa menit)..."
bash "$benchmark_dir/scripts/runFindSecBugs.sh"

if ! find "$benchmark_dir/results" -type f -name '*.xml' \
    \( -iname '*findsecbugs*' -o -iname '*findbugs*security*' -o -iname '*spotbugs*' \) \
    -print -quit 2>/dev/null | grep -q .; then
    echo "ERROR: Laporan XML FindSecBugs tidak ditemukan di $benchmark_dir/results." >&2
    exit 1
fi

echo "FindSecBugs siap. Jalankan skenario yang memuat FindSecBugs dengan ./scripts/run.sh."
