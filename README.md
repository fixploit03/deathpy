## DeathPy 📡

![](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![](https://img.shields.io/github/license/fixploit03/deathpy?style=flat)
![](https://img.shields.io/github/issues/fixploit03/deathpy?style=flat)
![](https://img.shields.io/github/stars/fixploit03/deathpy?style=flat)
![](https://img.shields.io/github/forks/fixploit03/deathpy?style=flat)

![](https://github.com/fixploit03/deathpy/blob/main/img/deathpy.png)

<div>
   <p align="center">
      | <a href="https://github.com/fixploit03/deathpy#deathpy-">Tentang</a>
      | <a href="https://github.com/fixploit03/deathpy/blob/main/INSTALL">Instalasi</a>
      | <a href="https://github.com/fixploit03/deathpy#penggunaan-">Penggunaan</a>
      | <a href="https://github.com/fixploit03/deathpy/blob/main/LICENSE">Lisensi</a> |
   </p>
</div>

`DeathPy` adalah program berbasis Python yang dirancang untuk tujuan pendidikan guna menunjukkan cara kerja serangan deautentikasi pada jaringan nirkabel (Wi-Fi). Program ini dibuat untuk digunakan dalam lingkungan yang terkontrol, seperti laboratorium keamanan siber atau pengujian penetrasi yang sah. Anda hanya boleh menggunakannya pada jaringan atau perangkat yang Anda miliki atau telah mendapatkan izin eksplisit dari pemiliknya untuk menguji keamanannya.

> :warning: **Disclaimer**: Program ini dibuat hanya untuk keperluan belajar dan pendidikan. Menggunakannya untuk tujuan ilegal, seperti mengganggu, menyusup, atau merusak jaringan tanpa izin, adalah melanggar hukum di banyak wilayah dan dapat menyebabkan konsekuensi hukum serius, termasuk denda atau penjara. Pembuat **(Rofi/Fixploit03)** tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh program ini. Tanggung jawab penuh ada pada pengguna untuk mematuhi hukum dan peraturan yang berlaku di wilayah Anda.

## Ilustrasi

![](https://github.com/fixploit03/deathpy/blob/main/img/ilustrasi%20serangan%20deauth.jpg)

Berikut ini adalah ilustrasi yang menunjukkan seorang penyerang (Attacker) mengirimkan Frame Deauthentication ke Access Point (AP), yang berfungsi sebagai perangkat untuk mendistribusikan koneksi internet. Dalam ilustrasi ini, AP menerima Frame Deauthentication, sehingga kemampuannya untuk menyebarkan koneksi internet terganggu dan tidak dapat berfungsi dengan normal. Akibatnya, perangkat seperti kamera CCTV, smartphone, dan kedua laptop kehilangan akses ke internet, sebagaimana ditandai dengan simbol "Disconnect" pada ilustrasi, yang menunjukkan dampak langsung dari serangan deautentikasi yang dilakukan oleh penyerang.

## Persyaratan 📦

- Sistem operasi Linux
- Antarmuka jaringan (Wi-Fi adapter) yang mendukung mode monitor (`TP-Link TLWN722N V2/V3` atau yang lain)
- Python 3.x
- Library `scapy` dan `termcolor`
- Kopi (Biar ga ngantuk ^_^)

> ✍🏼 **Catatan**: Pastikan driver untuk Wi-Fi adapter Anda sudah terinstal dengan benar. Anda bisa menemukan panduan instalasi driver di `YouTube` atau forum seperti `GitHub` dan `Stack Overflow`. Jika Wi-Fi adapter Anda tidak mendukung mode monitor, program tidak akan berfungsi sebagaimana mestinya.
## Instalasi 🔧

Panduan untuk menginstal DeathPy ada [disini](https://github.com/fixploit03/deathpy/blob/main/INSTALL).

## Penggunaan 👨‍💻

> Pastikan berada didalam folder `src` untuk menjalankan programnya.

```
usage: deathpy [-h] -b BSSID -c CHANNEL [-a CLIENT] [-n COUNT] [-t TIMEOUT] [-i INTERVAL] [-r {1,2,3,4,5,7,8,9,14,15}] [-v] interface
```

## Argumen 📝

Berikut adalah daftar argumen yang dapat Anda gunakan dalam program DeathPy:

| **Argumen** | **Deskripsi** | **Keterangan** |
|:--:|:--:|:--:|
| interface | Antarmuka jaringan (Wi-Fi adapter) dalam mode monitor (misalnya, wlan0). | Wajib |
| -b, --bssid | BSSID dari Access Point (AP) target (misalnya, 00:11:22:33:44:55). | Wajib |
| -c, --channel | Nomor channel tempat Access Point (AP) target beroperasi (contoh: 6). Nomor channel ini harus sesuai dengan konfigurasi Access Point (AP) agar serangan berhasil; Anda bisa mengetahuinya dengan memindai jaringan terlebih dahulu. | Wajib |
| -a, --client | MAC Address dari client yang akan dideauth (misalnya, 66:77:88:99:AA:BB). Jika tidak ditentukan, program akan memindai client dan mendeauth semua client yang ditemukan. | Opsional |
| -n, --count | Jumlah paket deautentikasi yang akan dikirim ke setiap client (contoh: 100). Gunakan 0 untuk mengirimkan paket secara terus-menerus hingga dihentikan secara manual dengan CTRL+C (default: 0). | Opsional |
| -t, --timeout | Durasi waktu (dalam detik) untuk memindai client yang terhubung ke Access Point (AP) sebelum memulai serangan (default: 30). Semakin lama waktu ini, semakin banyak client yang mungkin terdeteksi. | Opsional |
| -i, --interval | Jeda waktu (dalam detik) antara pengiriman setiap paket deautentikasi (contoh: 0.1). Nilai kecil akan mempercepat serangan, sementara nilai besar akan memperlambatnya (default: 0). | Opsional |
| -r, --reason | Kode alasan (reason code) yang menentukan mengapa client diputuskan dari jaringan (contoh: 15). Pilih salah satu dari 10 kode yang tersedia (lihat tabel di bawah) untuk menyesuaikan jenis serangan (default: 7). | Opsional |
| -v, --verbose | Mengaktifkan tampilan informasi tambahan selama serangan berlangsung. Jika digunakan, Anda akan melihat detail seperti nomor paket yang dikirim dan status setiap client yang diserang di terminal. | Opsional |


## Reason Codes untuk Serangan Deauthentication

Berikut adalah tabel yang menjelaskan 10 kode alasan (reason codes) paling umum yang digunakan dalam DeathPy untuk serangan deautentikasi. Kode-kode ini diambil dari standar IEEE 802.11 dan sering digunakan dalam pengujian keamanan jaringan karena efektivitasnya.

| **Kode Alasan** | **Deskripsi** | **Penjelasan Detail** |
|:--:|:--:|:--:|
| 1 | Unspecified reason | Pemutusan koneksi tanpa alasan spesifik. Kode ini bersifat generik dan sering digunakan karena tidak menarik perhatian sebagai serangan, sehingga cocok untuk menyamarkan aktivitas sebagai gangguan biasa. |
| 2 | Previous authentication no longer valid | Menunjukkan bahwa sesi autentikasi client telah kedaluwarsa, memaksa client untuk melakukan autentikasi ulang. Berguna untuk mengganggu koneksi yang sudah stabil dan memicu respons dari client. |
| 3 | Deauthenticated because sending STA is leaving | Meniru situasi di mana client tampak meninggalkan jaringan ad-hoc (IBSS) atau infrastruktur (ESS). Kode ini efektif untuk membuat pemutusan terlihat alami, seolah-olah client sengaja keluar dari jaringan. |
| 4 | Disassociated due to inactivity | Memutuskan koneksi client karena dianggap tidak aktif terlalu lama. Kode ini sering digunakan oleh Access Point (AP) untuk mengelola sumber daya, sehingga serangan dengan kode ini bisa disamarkan sebagai tindakan rutin Access Point (AP). |
| 5 | Disassociated because AP is unable to handle all associated STAs | Menunjukkan bahwa Access Point (AP) kelebihan beban dan tidak bisa mendukung semua client yang terhubung. Kode ini berguna untuk menyerang jaringan sibuk dan memaksa pemutusan client secara massal. |
| 7 | Class 3 frame received from nonassociated station | Menolak data dari client yang belum diasosiasikan dengan benar. Kode ini adalah default dalam banyak alat karena sifatnya yang teknis dan kemampuannya memutuskan koneksi dengan pasti. |
| 8 | Disassociated because sending STA is leaving BSS | Menunjukkan client meninggalkan Basic Service Set (BSS), misalnya karena berpindah lokasi. Kode ini cocok untuk menyamarkan serangan sebagai pemutusan akibat pergerakan perangkat. |
| 9 | STA requesting association is not authenticated | Memaksa client untuk autentikasi ulang dengan menyatakan bahwa status autentikasinya tidak valid. Berguna untuk mengganggu koneksi yang sedang berlangsung dan memicu respons dari client. |
| 14 | MIC failure (Message Integrity Check) | Menunjukkan adanya pelanggaran keamanan dalam komunikasi. Kode ini bisa memicu respons khusus dari jaringan yang aman dan sering digunakan untuk menguji mekanisme keamanan jaringan. |
| 15 | 4-way handshake timeout | client gagal menyelesaikan proses 4-way handshake dalam autentikasi WPA/WPA2. Ini memaksa perangkat klien untuk melakukan autentikasi ulang, sehingga memungkinkan serangan handshake capture untuk cracking password Wi-Fi. |

## Contoh ✨

1. Untuk mendeauth semua client yang terhubung ke Accees Point (AP) tertentu:
   
   ```
   sudo python3 deathpy.py wlan0 -b 00:11:22:33:44:55 -c 6
   ```

   Program akan memindai client yang terhubung ke Access Point (AP) dengan BSSID `00:11:22:33:44:55` pada channel `6`, lalu mengirimkan paket deautentikasi secara terus-menerus ke semua client yang ditemukan.

3. Mendeautentikasi client spesifik dengan reason code tertentu dan menampilkan output lebih rinci:
   
   ```
   sudo python3 deathpy.py wlan0 -b 00:11:22:33:44:55 -c 6 -a 66:77:88:99:AA:BB -r 15 -v
   ```

   Program akan Menyerang client dengan MAC Address `66:77:88:99:AA:BB` menggunakan reason code `15 (4-Way Handshake timeout)` dan menampilkan informasi tambahan selama serangan berlangsung. Anda akan melihat detail seperti nomor paket yang dikirim dan status setiap client yang diserang di terminal.

## Lisensi 📜

Program ini dilisensikan di bawah [Lisensi MIT](https://github.com/fixploit03/deathpy/blob/main/LICENSE).
