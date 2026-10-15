# CEOAI Juwet

Satu aplikasi Windows dengan dashboard terpadu untuk proxy dan cache.

- Proxy HTTP: port 8080
- HTTPS: CONNECT tunnel (bukan dekripsi TLS dalam rilis awal)
- Dashboard lokal: http://127.0.0.1:8787
- Cache HTTP persisten: ./data/cache
- Filter domain, log, statistik HIT/MISS
- TLS upstream tidak dinonaktifkan

## Menjalankan dari source
Memerlukan Node.js 22 atau lebih baru.

```powershell
npm install
npm test
npm start
```

Client dikonfigurasi memakai alamat IP komputer server dan port proxy 8080. Dashboard hanya bind ke localhost.

## EXE Windows
GitHub Actions akan membangun `CEOAI-Juwet.exe` dan mengunggah artefak setelah semua langkah build lulus. Simpan folder `data` di samping EXE agar cache dan log persisten.

Catatan: versi ini mendukung HTTPS CONNECT tunnel tetapi tidak mendekripsi atau meng-cache isi HTTPS.
