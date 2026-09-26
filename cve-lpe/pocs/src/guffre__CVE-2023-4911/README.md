# CVE-2023-4911
This is a PoC for CVE-2023-4911 ("Looney Tunables") that exploits a bug in the glibc dynamic loader's GLIBC_TUNABLES environment variable parsing function parse_tunables().

This is a rewrite of the C PoC's into a pure python approach. I did this to make it easier to customize the exploit for other platforms.
The only requirement is pwntools, which can be installed as follows:

    python3 -m pip install --upgrade pwntools

I got the original C PoC from: https://github.com/leesh3288/CVE-2023-4911

This code was tested on Ubuntu 22.04.3 with glibc version 2.35-0ubuntu3.1

# su offsets

This image shows the Ubuntu `su` executable. This is why `"` is chosen as the directory symbol, and the offset of -20 bytes points to that symbol:

![image](https://github.com/guffre/CVE-2023-4911/assets/21281361/aab8e766-344f-44ea-a2e6-2b5a5cca1730)

You should check the `su` binary on the machine you are targeting to make sure the offset and symbol are correct.
