#!/bin/sh
qemu-system-x86_64 \
	-m 8G \
	-nographic \
	-kernel bzImage \
	-append "root=/dev/sda rw trace_event=kmem:kmalloc,kmem:kmem_cache_alloc,kmem:kfree,kmem:kmalloc_node no_hash_pointers console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on nokaslr" \
	-no-reboot \
	-s \
	-cpu qemu64,+smap,+smep \
	-smp 2 \
	-monitor /dev/null \
	-drive file=disk.img,format=raw \
	-net nic,model=virtio \
	-net user
