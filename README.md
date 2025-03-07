## DeathPy 📡

![](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![](https://img.shields.io/github/license/fixploit03/deathpy?style=flat)
![](https://img.shields.io/github/issues/fixploit03/deathpy?style=flat)
![](https://img.shields.io/github/stars/fixploit03/deathpy?style=flat)
![](https://img.shields.io/github/forks/fixploit03/deathpy?style=flat)

![](https://github.com/fixploit03/deathpy/blob/main/img/ilustrasi%20serangan%20deauth.jpg)

**`DeathPy` adalah program Python yang dirancang untuk tujuan pendidikan untuk menunjukkan bagaimana serangan deauthentication bekerja dalam jaringan nirkabel (Wi-Fi).** Program ini ditujukan untuk digunakan dalam lingkungan yang terkontrol, seperti laboratorium keamanan siber atau pengujian penetrasi yang sah, dan hanya boleh digunakan pada jaringan atau perangkat yang Anda miliki atau memiliki izin eksplisit untuk diuji.

> :warning: **Disclaimer**: Program ini dibuat semata-mata untuk tujuan pendidikan. Penyalahgunaan program ini untuk kegiatan ilegal, seperti mengganggu atau merusak jaringan tanpa izin, adalah melanggar hukum dan dapat mengakibatkan konsekuensi hukum yang serius. Pembuat tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh penggunaan program ini. 

## Persyaratan 📦

- Sistem operasi Linux
- Antarmuka jaringan (Wi-Fi adapter) yang mendukung mode monitor (`TP-Link TLWN722N V2/V3` atau yang lain)
- Python 3.x
- Library `scapy` dan `termcolor`
- Kopi (Biar ga ngantuk ^_^)

> ✍🏼 **Catatan**: Jangan lupa untuk menginstal driver Wi-Fi adapternya. Panduan instalasinya banyak di YouTube.

## Instalasi 🔧

Panduan untuk menginstal DeathPy ada [disini](https://github.com/fixploit03/deathpy/blob/main/INSTALL).

## Penggunaan 👨‍💻

> Pastikan berada didalam folder `src` untuk menjalankan programnya.

```
sudo python3 deathpy.py <interface> -b <bssid> -c <channel> [-a <client>] [-n <count>] [-t <timeout>] [-i <interval>] [-v]
```

## Argumen 📝

| **Argumen** | **Deskripsi** | **Keterangan** |
|:--:|:--:|:--:|
| interface | Antarmuka jaringan (Wi-Fi adapter) dalam mode monitor (misalnya, wlan0). | Wajib |
| -b, --bssid | BSSID dari Access Point (AP) target (misalnya, 00:11:22:33:44:55). | Wajib |
| -c, --channel | Channel dari Access Point (AP) target (misalnya, 6). | Wajib |
| -a, --client | MAC Address dari client yang akan dideauth (misalnya, 66:77:88:99:AA:BB). Jika tidak ditentukan, program akan memindai client dan mendedeauth semua client yang ditemukan. | Opsional |
| -n, --count | Jumlah paket yang akan dikirim per client. Gunakan 0 untuk mode terus-menerus (default: 0). | Opsional |
| -t, --timeout | Waktu tunggu pemindaian client dalam detik (default: 30). | Opsional |
| -i, --interval | Interval antara pengiriman paket dalam detik (default: 0). | Opsional |
| -r, --reason | kode alasan (reason codes) yang digunakan dalam serangan deauthentication. | Opsional |
| -v, --verbose | Aktifkan output lebih rinci. | Opsional |


## Reason Codes untuk Serangan Deauthentication

Berikut adalah tabel yang menjelaskan kode alasan (reason codes) yang digunakan dalam serangan deauthentication. Kode-kode ini memberikan konteks tentang mengapa koneksi klien diputuskan.

| **Kode Alasan** | **Deskripsi** | **Penjelasan Detail** |
|:--:|:--:|:--:|
| **1** | **Unspecified reason** | Alasan generik dan tidak mencolok untuk pemutusan koneksi. Kode ini digunakan ketika tidak ada alasan spesifik yang dapat diberikan. Ini sering digunakan untuk menghindari deteksi atau untuk memberikan alasan yang tidak mencolok bagi pengguna. |
| **3** | **Deauthenticated because sending STA is leaving IBSS or ESS** | Kode ini menunjukkan bahwa perangkat (STA) yang mengirimkan paket deauthentication sedang meninggalkan jaringan ad-hoc (IBSS) atau jaringan infrastruktur (ESS). Ini dapat digunakan untuk meniru situasi di mana klien secara sah meninggalkan jaringan, sehingga tidak menimbulkan kecurigaan. |
| **4** | **Disassociated due to inactivity** | Memutuskan koneksi seolah-olah klien tidak aktif. Kode ini dapat digunakan untuk menguji pengaturan timeout pada perangkat klien, yang mungkin memutuskan koneksi jika tidak ada aktivitas dalam jangka waktu tertentu. |
| **7** | **Class 3 frame received from nonassociated STA** | Menolak data dari STA yang tidak terasosiasi. Kode ini menunjukkan bahwa perangkat tidak akan menerima data dari perangkat yang tidak terhubung ke jaringan. Ini adalah pengaturan default dalam banyak perangkat untuk menjaga keamanan jaringan. |
| **8** | **Disassociated because sending STA is leaving BSS** | Meniru situasi di mana perangkat (STA) yang mengirimkan paket deauthentication sedang meninggalkan Basic Service Set (BSS). Ini mirip dengan kode 3, tetapi lebih spesifik untuk jaringan infrastruktur. |
| **15** | **4-Way Handshake timeout** | Memaksa re-authentication, berguna untuk menangkap handshake WPA/WPA2. Kode ini digunakan untuk memaksa perangkat klien untuk melakukan proses autentikasi ulang, yang dapat digunakan untuk menangkap informasi penting dalam proses handshake. |

## Contoh ✨

Untuk mendeauth semua client yang terhubung ke Accees Point (AP) tertentu:

```
sudo python3 deathpy.py wlan0 -b 00:11:22:33:44:55 -c 6
```

Untuk mendeauth client tertentu:

```
usage: sudo python3 deathpy.py [-h] -b BSSID -c CHANNEL [-a CLIENT] [-n COUNT] [-t TIMEOUT] [-i INTERVAL] [-r REASON] [-v] interface
```


## Lisensi 📜

Program ini dilisensikan di bawah [Lisensi MIT](https://github.com/fixploit03/deathpy/blob/main/LICENSE).
