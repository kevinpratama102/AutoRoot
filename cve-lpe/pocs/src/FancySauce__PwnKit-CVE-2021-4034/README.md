# Pwnkit Exploit Instructions

I did not write this.  This is only to document my exection/instruction of exploit use as there are some very intricate and complicated steps to follow.  

Files come from the following source:
https://packetstormsecurity.com/files/165739/PolicyKit-1-0.105-31-Privilege-Escalation.html

Additional assistance on execution found here:
https://ine.com/blog/exploiting-pwnkit-cve-20214034

This was tested/executed on OSCP's Blackgate Practice VM:
	Ubuntu 20.04
	Kernel 5.8.0-63-generic
	
	
How to know if vulnerable:

Check for available SUID and make sure `/usr/bin/pkexec` is a SUID binary:
 `find / -perm -4000 2>/dev/null`
 
Check permissions of the binary:
`ls -al /usr/bin/pkexec`

Check pkexec version:

`/usr/bin/pkexec --version`

Vulnerable version found on Blackgate: `pkexec version 0.105`

Make sure compiler is available on the victim machine.
`gcc version`
	
# Exploit Execution

Copy the files over to the vicitm machine (Makefile, evil-so.c, exploit.c)
And compile using 'make all' command.
Execute './exploit'

Check shell

# Compilation errors
if you get an error stating that `cc: error trying to exec 'cc1': execvp: No such file or directory`.  
use `locate cc1' command to find the binaries:

```
locate cc1
/lib/modules/4.15.0-20-generic/kernel/drivers/iio/adc/cc10001_adc.ko
/lib/modules/4.15.0-20-generic/vdso/.build-id/a0/297fe29f8038ef50a10a26c9fcf5249ccc1184.debug
/usr/lib/gcc/x86_64-linux-gnu/7/cc1
/usr/lib/gcc/x86_64-linux-gnu/7/libcc1.so
/usr/lib/gcc/x86_64-linux-gnu/7/plugin/libcc1plugin.so
/usr/lib/gcc/x86_64-linux-gnu/7/plugin/libcc1plugin.so.0
/usr/lib/gcc/x86_64-linux-gnu/7/plugin/libcc1plugin.so.0.0.0
/usr/lib/x86_64-linux-gnu/libcc1.so.0
/usr/lib/x86_64-linux-gnu/libcc1.so.0.0.0

# Then Export the location to Path for reference, try to build again
Jack@oscp:/home/Jack$ export PATH=$PATH:/usr/lib/gcc/x86_64-linux-gnu/7/cc1
```



