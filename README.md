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
| 1 | Unspecified reason | Pemutusan koneksi tanpa alasan spesifik. Kode ini digunakan untuk mengakhiri koneksi tanpa memberikan detail lebih lanjut. Berguna untuk menyamarkan serangan agar terlihat seperti gangguan koneksi alami. |
| 3 | Deauthenticated because sending STA is leaving IBSS or ESS | Perangkat (STA) yang mengirimkan paket deauthentication dianggap keluar dari jaringan ad-hoc (IBSS) atau infrastruktur (ESS). Cocok untuk skenario di mana klien tampak seperti keluar secara alami. |
| 4 | Disassociated due to inactivity | Pemutusan koneksi karena dianggap tidak aktif. Kode ini biasa digunakan oleh AP untuk menghemat sumber daya jaringan dengan mengeluarkan klien yang tidak aktif dalam jangka waktu tertentu. Berguna untuk menyamarkan serangan sebagai kebijakan manajemen koneksi. |
| 7 | Class 3 frame received from nonassociated STA | Perangkat mengirim data tanpa melalui tahap autentikasi dan asosiasi yang benar. Kode ini sering digunakan oleh AP untuk menolak perangkat yang mencoba berkomunikasi tanpa melalui prosedur otentikasi yang sah. Berguna dalam serangan deauthentication karena memastikan klien benar-benar terputus. |
| 8 | Disassociated because sending STA is leaving BSS | Perangkat tampaknya keluar dari Basic Service Set (BSS). Ini meniru situasi di mana klien pindah ke area lain atau keluar dari jangkauan Wi-Fi. Berguna untuk menyamarkan serangan sebagai pemutusan alami akibat pergerakan perangkat. |
| 15 | 4-Way Handshake timeout | Klien gagal menyelesaikan proses 4-way handshake dalam autentikasi WPA/WPA2. Ini memaksa perangkat klien untuk melakukan autentikasi ulang, sehingga memungkinkan serangan handshake capture untuk cracking password Wi-Fi. |

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
