## Dissecting pkexec CVE-2021-4034

### Introduction and Usage
#### Introduction
This is a part of the [blog post](https://milot.io/dissecting-pkexec-cve-2021-43267-vulnerability/) that explains how [CVE-2021-4034](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) actually works.

#### Usage
This repository contains a single C file that contains code and comments, the compilation and running the file is fairly straight forward:

```
gcc pkexec-cve-2021-4034.c -o run-milotio
```

### Disclaimer
Please read the [disclaimer](https://milot.io/about/#disclaimer) below which is the same on my website, this vulnerability has been analyzed for ethical and educational purposes solely to understand how to protect your systems and environments.

All contents on this repository are for informational and educational purposes only. I strongly believe that computer programming, ethical hacking, information security and cyber security in general should be familiar subject to anyone using computers and the internet. Information and code posted on this repository should be used to understand topics from the defense perspective and in general how to protect yourself from various threat actors. Information on this repository is strictly for educational purposes and should be used ethically.

The entire content has been written on a controlled environment mainly using my own routers, servers, websites, computers and other resources (such as TryHackMe, HackTheBox and VulnHub) they do not contain any illegal activity. I don't promote, encourage, support or excite any illegal activity or hacking without written consent. I want to raise security awareness and inform the general opinion on how to prevent themselves from being a victim of malicious actors. If you plan to use the information for illegal purposes, please leave this blog now. I cannot be held responsible for any misuse of the given information.
