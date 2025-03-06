## DeathPy 📡

![](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![](https://img.shields.io/github/license/fixploit03/deathpy?style=flat)
![](https://img.shields.io/github/issues/fixploit03/deathpy?style=flat)
![](https://img.shields.io/github/stars/fixploit03/deathpy?style=flat)
![](https://img.shields.io/github/forks/fixploit03/deathpy?style=flat)


**`DeathPy` adalah program Python yang dirancang untuk tujuan pendidikan untuk menunjukkan bagaimana serangan deauthentication bekerja dalam jaringan nirkabel (Wi-Fi).** Program ini ditujukan untuk digunakan dalam lingkungan yang terkontrol, seperti laboratorium keamanan siber atau pengujian penetrasi yang sah, dan hanya boleh digunakan pada jaringan atau perangkat yang Anda miliki atau memiliki izin eksplisit untuk diuji.

> :warning: **Disclaimer**: Program ini dibuat semata-mata untuk tujuan pendidikan. Penyalahgunaan program ini untuk kegiatan ilegal, seperti mengganggu atau merusak jaringan tanpa izin, adalah melanggar hukum dan dapat mengakibatkan konsekuensi hukum yang serius. Pembuat tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh penggunaan program ini. 

## Persyaratan 📦

- Sistem operasi Linux
- Antarmuka jaringan (Wi-Fi adapter) yang mendukung mode monitor (`TP-Link TLWN722N V2/V3` atau yang lain)
- Python 3.x
- Library `scapy` dan `termcolor`
- Kopi (Biar ga ngantuk ^_^)

## Instalasi 🔧

Panduan untuk menginstal DeathPy ada disini [here]()

## Penggunaan 👨‍💻

> Pastikan berada didalam folder `src` untuk menjalankan program nya.

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
| -v, --verbose | Aktifkan output lebih rinci. | Opsional |

## Contoh ✨

Untuk mendeauth semua client yang terhubung ke Accees Point (AP) tertentu:

```
sudo python3 deathpy.py wlan0 -b 00:11:22:33:44:55 -c 6
```

Untuk mendeauth client tertentu:

```
sudo python3 deathpy.py wlan0 -b 00:11:22:33:44:55 -c 6 -a 66:77:88:99:AA:BB
```

## Lisensi 📜

Program ini dilisensikan di bawah [Lisensi MIT]().
