# -*- coding: utf-8 -*-
"""Tabel data lpescan — displice ke dist/lpescan.py oleh build-scanner.py.
HANYA berisi literal data, tanpa import/dokumen panjang."""

# dpkg/rpm package name (fnmatch) -> [(vendor, product)] CPE
PKG_TO_CPE = {
    "sudo":            [("todd_miller", "sudo"), ("sudo_project", "sudo")],
    "libc6":           [("gnu", "glibc")],
    "glibc":           [("gnu", "glibc")],
    "libc6-*":         [("gnu", "glibc")],
    "bash":            [("gnu", "bash")],
    "coreutils":       [("gnu", "coreutils")],
    "util-linux":      [("andries_brouwer", "util-linux"), ("kernel", "util-linux")],
    "policykit-1":     [("polkit_project", "polkit")],
    "polkitd":         [("polkit_project", "polkit")],
    "polkit":          [("polkit_project", "polkit")],
    "snapd":           [("canonical", "snapd")],
    "apport":          [("canonical", "apport")],
    "python-apport":   [("canonical", "apport")],
    "dbus":            [("freedesktop", "libdbus")],
    "dbus-daemon":     [("freedesktop", "libdbus")],
    "libdbus-1-*":     [("freedesktop", "libdbus")],
    "openssl":         [("openssl", "openssl")],
    "libssl*":         [("openssl", "openssl")],
    "libcrypto*":      [("openssl", "openssl")],
    "perl":            [("perl", "perl")],
    "perl-base":       [("perl", "perl")],
    "perl-*":          [("perl", "perl")],
    # interpreter-only: python3*/python-* terlalu greedy — python-apt-common 3.0.0
    # & python3-aiodns 3.5.0-1 (modul pihak ketiga) kebetulan masuk constraint
    # python:python. Cuma paket yang MEMBAWA interpreter yang dipetakan.
    # Lini python2 TIDAK dipetakan: constraint satu-sisi (mis. [<=3.7.12]) akan
    # menangkap 2.7.18 secara numerik (CVE-2022-26488 vs python2-minimal) —
    # false positive antar-major-line; py2 EOL & box murni-py2 praktis tidak ada.
    "python3":         [("python", "python")],
    "python3.[0-9]*":  [("python", "python")],
    "python3-minimal": [("python", "python")],
    "python3-dev":     [("python", "python")],
    "libpython3*":     [("python", "python")],
    "rpm":             [("rpm", "rpm")],
    "rpm-libs":        [("rpm", "rpm")],
    "xen*":            [("xen", "xen")],
    "qemu*":           [("qemu", "qemu")],
    "openldap":        [("openldap", "openldap")],
    "slapd":           [("openldap", "openldap")],
    "libldap*":        [("openldap", "openldap")],
    "postgresql":      [("postgresql", "postgresql")],
    "postgresql-*":    [("postgresql", "postgresql"), ("debian", "postgresql-common")],
    "samba":           [("samba", "samba")],
    "smbd":            [("samba", "samba")],
    "samba-common":    [("samba", "samba")],
    "rsync":           [("samba", "rsync")],
    "cifs-utils":      [("samba", "cifs-utils")],
    "zlib1g":          [("zlib", "zlib")],
    "zlib":            [("zlib", "zlib")],
    "libexpat1":       [("libexpat_project", "libexpat")],
    "expat":           [("libexpat_project", "libexpat")],
    "libxml2":         [("xmlsoft", "libxml2")],
    "libxml2-*":       [("xmlsoft", "libxml2")],
    "libssh*":         [("libssh", "libssh")],
    "sqlite3":         [("sqlite", "sqlite")],
    "libsqlite3*":     [("sqlite", "sqlite")],
    "systemd":         [("systemd_project", "systemd")],
    "systemd-*":       [("systemd_project", "systemd")],
    # cups* dipecah: cups-pk-helper 0.2.6 (helper polkit, versi sendiri) &
    # apcupsd (daemon UPS) kebetulan masuk constraint apple:cups/cups-filters
    # secara numerik (CVE-2022-26691 [<499.4], CVE-2013-6476 [<=1.0.46]).
    # Hanya paket dari sumber CUPS / cups-filters yang dipetakan.
    "cups":            [("apple", "cups"), ("openprinting", "cups")],
    "cups-common":     [("apple", "cups"), ("openprinting", "cups")],
    "cups-client":     [("apple", "cups"), ("openprinting", "cups")],
    "cups-server":     [("apple", "cups"), ("openprinting", "cups")],
    "cups-daemon":     [("apple", "cups"), ("openprinting", "cups")],
    "libcups*":        [("apple", "cups"), ("openprinting", "cups")],
    "cups-filters":    [("linuxfoundation", "cups-filters")],
    "cups-filters-*":  [("linuxfoundation", "cups-filters")],
    "libcupsfilters*": [("linuxfoundation", "cups-filters")],
    "apache2":         [("apache", "http_server")],
    "httpd":           [("apache", "http_server")],
    "tomcat*":         [("apache", "tomcat")],
    "nginx*":          [("nginx", "nginx"), ("f5", "nginx")],
    "firefox":         [("mozilla", "firefox")],
    "firefox-*":       [("mozilla", "firefox")],
    "thunderbird":     [("mozilla", "thunderbird")],
    "curl":            [("haxx", "curl")],
    "libcurl*":        [("haxx", "libcurl"), ("haxx", "curl")],
    "wget":            [("gnu", "wget")],
    "tar":             [("gnu", "tar")],
    "gawk":            [("gnu", "gawk")],
    "findutils":       [("gnu", "findutils")],
    "screen":          [("gnu", "screen"), ("juergen", "weigert_screen")],
    "tmux":            [("nicholas_marriott", "tmux")],
    "procps":          [("procps-ng_project", "procps-ng")],
    "procps-ng":       [("procps-ng_project", "procps-ng")],
    # exact-only: openssh* ikut menangkap openssh-client-ssh1 (legacy 1:7.5p1)
    # & openssh-sftp-server — versi lama yang menyesatkan match CVE openssh
    "openssh-server":  [("openbsd", "openssh")],
    "openssh-client":  [("openbsd", "openssh")],
    "bind9*":          [("isc", "bind")],
    "bind":            [("isc", "bind")],
    # krb5-* = MIT Kerberos (1.x); eyrie:pam-krb5 itu modul PAM versi 3.x/4.x —
    # krb5-locales 1.22.1 kebetulan lolos constraint pam-krb5 [<=3.12] secara
    # numerik (CVE-2009-0360), salah produk. kerberos_project:kerberos (Heimdal
    # 7.x) TIDAK dipetakan — sama rawan coincidence antar-major-line.
    "krb5-*":          [("mit", "kerberos_5"), ("mit", "kerberos")],
    "libpam-krb5":     [("eyrie", "pam-krb5")],
    "shadow":          [("shadow_project", "shadow"), ("suse", "shadow")],
    "login":           [("shadow_project", "shadow")],
    "passwd":          [("shadow_project", "shadow")],
    "exim4*":          [("exim", "exim"), ("university_of_cambridge", "exim")],
    "postfix":         [("postfix", "postfix")],
    "sendmail*":       [("sendmail", "sendmail"), ("eric_allman", "sendmail")],
    "dovecot*":        [("dovecot", "dovecot")],
    "proftpd*":        [("proftpd", "proftpd"), ("proftpd_project", "proftpd")],
    "pure-ftpd*":      [("pureftpd", "pure-ftpd")],
    "lighttpd":        [("lighttpd", "lighttpd")],
    "php*":            [("php", "php")],
    "expect":          [("don_libes", "expect")],
    "policycoreutils": [("redhat", "policycoreutils")],
    "language-selector*": [("ubuntu", "language-selector")],
}

# distro id (/etc/os-release ID) -> [(vendor, product)] CPE untuk pin distro
DISTRO_TO_CPE = {
    "debian":        [("debian", "debian_linux")],
    "ubuntu":        [("canonical", "ubuntu_linux")],
    "fedora":        [("fedoraproject", "fedora")],
    "rhel":          [("redhat", "enterprise_linux_server"),
                      ("redhat", "enterprise_linux_desktop"),
                      ("redhat", "enterprise_linux_workstation")],
    "redhat":        [("redhat", "enterprise_linux_server")],
    "centos":        [("redhat", "enterprise_linux_server")],
    "opensuse-leap": [("opensuse", "leap")],
    "opensuse":      [("opensuse", "opensuse")],
    "sles":          [("suse", "suse_linux")],
    "kali":          [("debian", "debian_linux")],
}

# Windows: release token (huruf kecil, tanpa 'windows_') -> build number dasar
WIN_RELEASE_TO_BUILD = {
    "windows_10": {
        "1507": 10240, "1511": 10586, "1607": 14393, "1703": 15063,
        "1709": 16299, "1803": 17134, "1809": 17763, "1903": 18362,
        "1909": 18363, "2004": 19041, "20h2": 19042, "21h1": 19043,
        "21h2": 19044, "22h2": 19045,
    },
    "windows_11": {
        "21h2": 22000, "22h2": 22621, "23h2": 22631,
        "24h2": 26100, "25h2": 26100, "26h1": 26100,
    },
    "windows_server_2008": {"sp2": 6002},
    "windows_server_2008_r2": {"sp1": 7601},
    "windows_server_2012": {"": 9200},
    "windows_server_2012_r2": {"": 9600},
    "windows_server_2016": {"1607": 14393, "1809": 17763, "1903": 18362, "1909": 18363},
    "windows_server_2019": {"1809": 17763, "1903": 18362, "1909": 18363},
    "windows_server_2022": {"21h2": 20348},
    "windows_server_2022_23h2": {"23h2": 25398},
    "windows_server_2025": {"24h2": 26100},
    "windows_7": {"sp1": 7601},
    "windows_8.1": {"": 9600},
    "windows_rt_8.1": {"": 9600},
}

# basename (fnmatch, lowercase) biner SUID yang dikenal berbahaya (GTFOBins-style)
GTFO_SUIDS = [
    "find", "vim*", "nano", "less", "more", "awk", "gawk", "python*", "perl",
    "ruby*", "php*", "bash", "dash", "sh", "zsh", "env", "cp", "mv", "tar",
    "unzip", "zip", "ssh", "scp", "sftp", "curl", "wget", "socat", "nc",
    "ncat", "pkexec", "mount", "umount", "fusermount*", "su", "ping", "ping6",
    "passwd", "chsh", "chfn", "newgrp", "gpasswd", "sudoedit", "tcpdump",
    "capsh", "setcap", "getcap", "systemctl", "journalctl", "busctl", "crontab",
    "at", "flock", "comm", "csplit", "cut", "diff", "expand", "fmt", "fold",
    "head", "join", "nl", "od", "paste", "pr", "sed", "sort", "split", "tail",
    "tee", "tr", "uniq", "xxd", "base64", "openssl", "date", "timeout", "watch",
    "node*", "lua*", "ruby*", "cpan", "gdb", "strace", "taskset", "chroot",
    "nsenter", "unshare", "bwrap", "rpm", "dpkg", "apt*", "dockerd", "docker",
    "runuser", "pkill", "pgrep", "ps", "top", "htop", "ionice", "nice", "nohup",
    "printf", "echo", "sleep", "uptime", "w", "who", "id", "groups", "csh",
    "ksh", "expect", "screen", "tmux", "script", "mail", "mutt", "git", "hg",
    "svn", "rsh", "rlogin", "tclsh*", "wish*", "dbus*", "gcore", "javac", "java",
]

# privilege Windows yang menarik + saran exploit
WIN_INTERESTING_PRIVS = {
    "SeImpersonatePrivilege": "Potato family (JuicyPotato/PrintSpoofer/GodPotato)",
    "SeAssignPrimaryTokenPrivilege": "Potato family (JuicyPotato/PrintSpoofer)",
    "SeBackupPrivilege": "robocopy /b atau reg save SAM/SYSTEM + secretsdump",
    "SeRestorePrivilege": "tulis file sistem (ganti driver/service binary)",
    "SeDebugPrivilege": "injeksi ke proses SYSTEM (mimikatz / token steal)",
    "SeTakeOwnershipPrivilege": "ambil kepemilikan file sistem lalu modifikasi",
    "SeLoadDriverPrivilege": "load driver rentan (Capcom / BYOVD)",
    "SeCreateTokenPrivilege": "buat token sendiri (potensi SYSTEM)",
    "SeTcbPrivilege": "bertindak sebagai bagian OS (setara SYSTEM)",
    "SeEnableDelegationPrivilege": "delegasi token (relay/kerberoast vector)",
}
