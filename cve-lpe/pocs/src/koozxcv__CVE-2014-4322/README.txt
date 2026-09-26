poc code works on Nexus 5 Android4.4.4 
Gain privileges：system->root，as part of https://github.com/koozxcv/CVE-2014-7911-CVE-2014-4322_get_root_privilege

author：andy
website：https://blog.csdn.net/koozxcv

The exploit must be excuted as system privilege and serveral specific SELinux context.If exploit successed，you will gain root
privilege and “kernel” SELinux context.

bug info
https://www.codeaurora.org/projects/security-advisories/memory-corruption-qseecom-driver-cve-2014-4322

how to build
ndk-build

usage
Kitkat:
run exploit as system privilege

Lolipop:
run exploit as system privilege,with SELinux context such as "keystore","vold","drmserver","mediaserver","surfaceflinger"

If exploit successed,you will gain root privilege and "kernel" SELinux context
