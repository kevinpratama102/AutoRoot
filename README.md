# AutoRoot
NOTE: PENJELASAN LENGKAP LOCAL PRIVILEGE ESCALATION (LPE) DAN 20 METODE EKSPLOITASI

1. PENGERTIAN LOCAL PRIVILEGE ESCALATION (LPE)
Local Privilege Escalation adalah tahap di mana attacker yang sudah memiliki akses awal (sebagai user biasa atau user service seperti www-data) mencari celah keamanan untuk meningkatkan hak aksesnya menjadi root atau user dengan level lebih tinggi. LPE biasanya memanfaatkan kerentanan pada kernel, kesalahan konfigurasi sistem, atau kecerobohan admin (human error).
=========================================================
2. DAFTAR 20 METODE EKSPLOITASI LPE DAN MISKONFIGURASI

Berikut adalah 20 metode yang sering digunakan dalam proses penetrasi sistem Linux:

Metode 1: Eksploitasi Kernel (uname -a)
Mencari bug pada versi kernel OS. Jika kernel belum di-patch, attacker menggunakan exploit (seperti Dirty Pipe atau Dirty COW) untuk mendapatkan akses root.

Metode 2: SUID Binaries (GTFOBins)
Mencari file binary dengan bit SUID aktif yang memungkinkan file dijalankan dengan hak akses pemiliknya (root). Contoh: binari find, vim, atau nano yang salah konfigurasi.

Metode 3: Sudo Tanpa Password (sudo -l)
Memeriksa perintah apa saja yang bisa dijalankan user dengan sudo tanpa memerlukan password (NOPASSWD). Jika binari seperti python atau perl ada di daftar, akses root bisa didapat instan.

Metode 4: Localhost Web Service (No Auth)
Mengakses layanan web internal yang hanya bisa diakses via 127.0.0.1. Jika layanan tersebut jalan sebagai root dan memiliki fitur eksekusi perintah (RCE) tanpa login, sistem bisa ditembus.

Metode 5: Docker Daemon (Port 2375)
Memanfaatkan docker socket yang terbuka di localhost. User biasa bisa menjalankan container yang me-mount filesystem host ke dalam container untuk memodifikasi file root.

Metode 6: Redis Misconfiguration
Redis yang jalan sebagai root di localhost tanpa password bisa dimanfaatkan untuk menulis authorized_keys atau membuat cronjob backconnect.

Metode 7: Credential Access via Shell History
Mengecek file .bash_history atau .zsh_history. Sering ditemukan admin menuliskan password database atau password sudo secara tidak sengaja di terminal.

Metode 8: SSH Key Hijacking
Mengambil private key (id_rsa) dari direktori .ssh user lain yang memiliki akses ke root atau ke server lain via localhost.

Metode 9: TTY Inject (Persistence)
Menggunakan tool seperti ttyinject untuk membajak sesi terminal. Saat root login ke user yang kita pegang, kita bisa otomatis mengambil alih sesi tersebut menjadi root.

Metode 10: Pkexec (CVE-2021-4034)
Eksploitasi pada PolicyKit (PoliKit) yang belum di-update. Ini adalah salah satu cara paling stabil untuk mendapatkan root pada distro Linux lama.

Metode 11: Writable /etc/passwd
Jika file /etc/passwd bisa ditulis oleh user biasa, attacker bisa menambahkan user baru dengan UID 0 atau menghapus password root langsung dari file tersebut.

Metode 12: Wildcard Injection pada Cronjob
Memanfaatkan cronjob yang menggunakan tanda bintang (*) dalam perintahnya (misal: tar). Attacker bisa membuat file dengan nama yang menyerupai flag perintah untuk mengeksekusi script.

Metode 13: LD_PRELOAD Sudo Exploit
Jika env_keep mengandung LD_PRELOAD, attacker bisa memuat library shared object (.so) buatan sendiri saat menjalankan perintah sudo untuk mendapatkan shell root.

Metode 14: D-Bus Service Exploitation
Mengirim perintah ke layanan sistem melalui D-Bus API di localhost yang tidak membatasi akses user biasa.

Metode 15: NFS No_Root_Squash
Jika sistem berbagi folder via NFS dengan opsi no_root_squash, attacker bisa me-mount folder tersebut dari mesin luar, memasukkan binary SUID, dan menjalankannya di mesin target.

Metode 16: Capabilities Exploitation
Mengecek file yang memiliki "Capabilities" khusus (getcap). Misalnya, binari python dengan CAP_SETUID bisa dimanfaatkan untuk mengubah UID menjadi 0.

Metode 17: Password Reuse (Database Config)
Mengambil password dari file konfigurasi aplikasi (seperti wp-config.php) dan mencoba password tersebut untuk user sistem atau root.

Metode 18: Python Library Hijacking
Jika script root mengimpor library python dari direktori yang bisa ditulis oleh user biasa, attacker bisa menaruh library palsu berisi kode jahat.

Metode 19: Exploiting Writable PATH
Jika direktori di dalam variable $PATH (seperti /usr/local/bin) bisa ditulis, attacker bisa menaruh binari palsu (seperti ls atau cat) yang akan dijalankan oleh user lain atau root.

Metode 20: Automated Recon (LinPeas)
Menggunakan script LinPeas untuk memindai semua celah di atas secara otomatis. Script ini memberikan laporan detail mengenai jalur tercepat untuk menjadi root.
===================================================
3. KESIMPULAN
LPE bukan hanya soal exploit canggih, tapi sering kali soal ketelitian dalam melihat celah kecil pada konfigurasi lokal. Di wilayah seperti Indonesia dan Thailand, kecerobohan admin dalam mengatur password dan layanan localhost adalah pintu masuk yang paling sering berhasil ditembus.
