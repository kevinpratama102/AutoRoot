TARGET=/home/xen/cve-2013-2072/result/
cp /var/log/user.log /var/log/xen/xend.log $TARGET
test -e /var/log/heap_dump.dat && cp /var/log/heap_dump.dat $TARGET
