# CEOAI Juwet

CEOAI Juwet adalah aplikasi desktop Windows satu jendela (tanpa browser/dashboard terpisah) untuk proxy HTTP/HTTPS, cache lokal, filter domain, rewrite URL, dan cache cleaner. HandyCache yang diberikan pemilik proyek digunakan sebagai **referensi konsep/alur fitur**, bukan sebagai sumber kode yang disalin.

## Fitur yang dibangun ulang dari konsep referensi

- **Monitor:** statistik request, cache HIT/MISS, bypass, blokir, volume data, serta log aktivitas terkini.
- **Cache Manager:** cache HTTP persisten di folder `data/cache`, pembersihan cache kedaluwarsa secara manual/terjadwal, dan tombol purge.
- **Web Filters:** blocklist dan allowlist domain.
- **Rewrite Rules:** penggantian teks URL sebelum request HTTP diteruskan.
- **Offline / read-from-cache:** jika diaktifkan, request yang tidak ada dalam cache menerima respons 504 tanpa membuat koneksi upstream.
- **Port proxy:** `8080`.
- **Dashboard:** `http://127.0.0.1:8787`, hanya terikat ke localhost.

## HTTPS dan keamanan

Secara default, HTTPS bekerja sebagai **CONNECT tunnel** tanpa dekripsi; browser tetap memvalidasi TLS situs tujuan. Fitur inspeksi TLS dapat diaktifkan secara eksplisit untuk lingkungan yang berwenang, sebagaimana dijelaskan pada bagian di bawah. Cache HTTP hanya digunakan untuk request GET yang tidak memakai cookie/authorization dan tidak dilarang oleh kebijakan cache server. Verifikasi sertifikat TLS upstream tetap aktif.

Proxy mendengarkan pada semua interface jaringan agar perangkat LAN dapat menggunakannya. Gunakan hanya pada jaringan tepercaya; versi awal belum menyediakan autentikasi proxy. Dashboard dibatasi ke localhost.

## Aplikasi Windows

Jalankan `CEOAI-Juwet.exe`. Jendela aplikasi terbuka langsung dan menampilkan monitor serta kontrol di dalam satu aplikasi; tidak perlu membuka dashboard secara manual di browser. Proxy menggunakan port `8080`, dashboard lokal internal `8787`.

## Menjalankan dari source

Memerlukan Node.js 22 atau lebih baru.

```powershell
npm install
npm test
npm start
```

Atur browser/perangkat klien agar menggunakan IP komputer server dan port proxy `8080`. Dashboard dibuka di komputer server melalui `http://127.0.0.1:8787`.

## EXE Windows

GitHub Actions menguji source, membangun `CEOAI-Juwet.exe`, menguji EXE hasil paket, lalu mengunggah artefak bersama ZIP source jika seluruh langkah lulus. Simpan folder `data` di samping EXE agar cache/log/filter/config bertahan saat aplikasi ditutup atau diperbarui.

Ini adalah implementasi baru yang terinspirasi konsep proxy/cache klasik, bukan salinan aplikasi atau kode HandyCache.


## Inspeksi TLS dan cache HTTPS (opt-in)

Inspeksi TLS tersedia sebagai fitur **opsional dan nonaktif secara default**. Aktifkan hanya untuk perangkat/jaringan yang Anda miliki atau berwenang kelola. Perangkat klien harus mempercayai sertifikat publik CA lokal melalui menu `/api/tls/ca.pem`; jangan membagikan private key CA. Private key disimpan di `data/tls/ca-key.pem` dan sertifikat CA di `data/tls/ca-cert.pem`.

Status dapat diperiksa melalui `GET /api/tls/status`. Pengaturan `tlsInspectionEnabled: true` dapat dikirim melalui `POST /api/config` setelah dashboard lokal aktif. Untuk menonaktifkan kembali kirim `tlsInspectionEnabled: false`. Saat inspeksi aktif, hanya koneksi CONNECT ke port 443 yang dialihkan ke jalur inspeksi. Sertifikat upstream tetap diverifikasi oleh klien Node.js ketika membuat koneksi HTTPS; jangan gunakan proxy untuk melewati peringatan sertifikat situs. Kebijakan cache HTTP yang sama tetap berlaku: permintaan ber-cookie/Authorization tidak di-cache, dan respons yang privat atau melarang penyimpanan harus bypass.

**Peringatan:** inspeksi TLS dapat membuat isi HTTPS—termasuk informasi sensitif—terlihat oleh proses lokal. Gunakan persetujuan eksplisit, akses perangkat yang terbatas, dan firewall. Pengujian integrasi TLS/HTTPS dan smoke test EXE pada workflow Windows telah lulus pada build yang diperiksa; ini bukan jaminan bebas bug atau sertifikasi keamanan untuk semua lingkungan produksi.
