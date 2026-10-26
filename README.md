# SAST LLM Benchmark

Repository ini berisi dataset OWASP Benchmark Java, prompt, runner berbasis
Ollama, dan hasil eksperimen. Panduan ini menjelaskan cara menyiapkan lingkungan
baru dan menjalankan eksperimen dari clone yang bersih.

## Prasyarat

- Linux/macOS dengan Bash
- Python 3.10 atau lebih baru
- [Ollama](https://ollama.com/) terpasang dan berjalan secara lokal
- Ruang disk dan RAM yang cukup untuk model Ollama yang dipilih

Runner menggunakan standard library Python, jadi tidak perlu memasang paket
Python tambahan. Untuk menjalankan skenario FindSecBugs, juga diperlukan Git,
Java, dan Maven.

## Persiapan eksperimen LLM

Dari root repository:

```bash
./scripts/prepare.sh
```

Skrip memvalidasi versi Python, dataset, prompt, dan runner. Tidak ada perubahan
atau instalasi sistem yang dilakukan oleh persiapan standar.

Pastikan server Ollama berjalan. Jika belum, jalankan di terminal terpisah:

```bash
ollama serve
```

Di terminal lain, unduh satu model yang didukung runner. Model-model ini besar;
pilih sesuai kapasitas mesin:

```bash
ollama pull deepseek-coder:6.7b
# Alternatif:
# ollama pull qwen2.5-coder:7b
# ollama pull gemma4:e4b
```

Jalankan pilot lima sampel untuk satu skenario:

```bash
./scripts/run.sh --scenario baseline-1 \
  --model deepseek-coder:6.7b \
  --limit 5
```

Runner meminta konfirmasi sebelum memanggil model. Tanpa `--scenario`, runner
menampilkan menu untuk memilih model dan skenario. Gunakan `--help` untuk
melihat opsi, termasuk batas waktu dan pilihan resume.

Skenario tanpa SAST dapat dijalankan dengan `baseline-1`, `zero-shot-none`,
`cot-none`, atau `tot-none`. Perintah tanpa `--limit` memproses seluruh dataset;
jalankan pilot terlebih dahulu karena inferensi dapat memakan waktu dan sumber
daya yang signifikan.

## Menyiapkan FindSecBugs (opsional)

Skenario FindSecBugs menggunakan checkout BenchmarkJava v1.2 yang terpisah dan
plugin BenchmarkUtils. Opsi berikut mengambil checkout ke folder `benchmark/`
(folder ini diabaikan Git), menginstal BenchmarkUtils ke Maven lokal, lalu
menjalankan scanner:

```bash
./scripts/prepare.sh --with-sast
```

Perlu koneksi internet dan waktu untuk mengunduh dependensi serta menjalankan
build. Jika `benchmark/BenchmarkJava` sudah ada, skrip memeriksa isinya dan
tidak menimpanya. Setelah persiapan selesai, skenario `baseline-2`,
`zero-shot-findsecbugs`, `cot-findsecbugs`, dan `tot-findsecbugs` dapat
dijalankan lewat `./scripts/run.sh`.

## Hasil dan reproduksibilitas

- JSONL setiap percobaan dan ringkasan tersimpan di `results/llm/raw/`.
- Runner mencatat hash dataset, prompt, dan laporan SAST beserta konfigurasi
  model untuk membantu membedakan hasil eksperimen.
- Hasil dan berkas lokal di `benchmark/` tidak otomatis di-commit atau
  dipublikasikan.
- Untuk membangun dataset kembali dari checkout BenchmarkJava, gunakan:

  ```bash
  python3 scripts/prepare_llm_dataset.py \
    --ground-truth benchmark/BenchmarkJava/expectedresults-1.2.csv \
    --source-dir benchmark/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \
    --output /tmp/sast-llm-dataset.jsonl
  ```

  Gunakan lokasi output lain seperti contoh agar dataset yang sudah ada di
  `llm/dataset.jsonl` tidak tertimpa.
