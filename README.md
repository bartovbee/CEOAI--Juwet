# CEOAI Juwet

CEOAI Juwet adalah aplikasi desktop Windows satu jendela (tanpa browser/dashboard terpisah) untuk proxy HTTP/HTTPS, cache lokal, filter domain, rewrite URL, dan cache cleaner. HandyCache yang diber[...]

## Inspeksi TLS dan cache HTTPS (opt-in)

Inspeksi TLS tersedia sebagai fitur **opsional dan nonaktif secara default**. Aktifkan hanya untuk perangkat/jaringan yang Anda miliki atau berwenang kelola. Perangkat klien harus mempercayai sertifikat CA lokal agar browser menerima sertifikat leaf yang dihasilkan oleh proses inspeksi.

Lihat dokumentasi lebih rinci di docs/TLS_INSPECTION.md untuk langkah-langkah mengunduh CA, memasangnya di Windows/macOS/Linux, dan mengonfigurasi browser agar menggunakan proxy sehingga caching HTTPS dapat bekerja.

Status dapat diperiksa melalui `GET /api/tls/status`. Pengaturan `tlsInspectionEnabled: true` dapat dikirim melalui `POST /api/config` setelah dashboard lokal aktif. Untuk menonaktifkan kembali ki[...]
