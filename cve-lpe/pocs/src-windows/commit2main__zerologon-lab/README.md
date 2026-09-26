# zerologon-lab

Scripts for a lab environment demonstrating the Zerologon (CVE-2020-1472) vulnerability.

## Usage

### [`zerologon.py`](zerologon.py)

```sh
zerologon.py [-h] [--reset] [--restore HEX] dc_name dc_ip
```

Attempt to exploit the Zerologon vulnerability against a Domain Controller. Arguments:

- `dc_name`: The NetBIOS name of the target Domain Controller.
- `dc_ip`: The IP address of the target Domain Controller.
- `--reset`: Optional flag to reset the machine account password to an empty string. The script only tests for the vulnerability by default.
- `--restore HEX`: Optional argument to restore the machine account password from a dumped hex password post-exploitation.
- `-h`, `--help`: Show help message and exit.
