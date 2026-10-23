# Auto-commit ke `origin`

Skrip `scripts/auto_commit.py` memeriksa working tree secara berkala. Jika ada perubahan, skrip akan melakukan `git add --all`, membuat commit, lalu menjalankan `git push origin HEAD` pada branch aktif. Berkas yang di-ignore Git tidak ikut kecuali opsi `--include-ignored` dipakai.

```bash
# Periksa tiap 5 menit (default)
python3 scripts/auto_commit.py

# Interval 2 menit
python3 scripts/auto_commit.py --interval 2

# Sekali saja; cocok untuk verifikasi
python3 scripts/auto_commit.py --once

# Simulasi; tidak mengubah index/commit/push
python3 scripts/auto_commit.py --once --dry-run

# Ubah awalan subject commit
python3 scripts/auto_commit.py --interval 10 --message "chore: backup"
```

Tekan `Ctrl+C` untuk menghentikan. Pastikan autentikasi GitHub untuk `git push` sudah tersedia dan branch aktif memiliki upstream/izin push. Perhatikan bahwa `git add --all` memasukkan **semua perubahan non-ignored di repository**, termasuk perubahan yang mungkin belum ingin dipublikasikan. Jangan jalankan ketika ada perubahan lokal sensitif atau yang belum siap dikirim.
