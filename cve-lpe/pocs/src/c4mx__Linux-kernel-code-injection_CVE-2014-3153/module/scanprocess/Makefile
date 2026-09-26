
obj-m := scanprocess.o
scanprocess-objs := disk.o main.o

KVER ?= zedboard-3.10

KDIR := /home/c4mx/y/linux-3.10-support-modules

PWD := $(shell pwd)

.PHONY: modules modules_install clean distclen help

default:
	$(MAKE) ARCH=arm CROSS_COMPILE=arm-none-eabi- -C $(KDIR) EXTRA_CFLAGS=-fno-pic M=$(PWD) modules
	mv scanprocess.ko scanprocess-$(KVER).ko

debug:
	KCFLAGS="-DLIME_DEBUG" $(MAKE) ARCH=arm CROSS_COMPILE=arm-none-eabi-  -C $(KDIR)  EXTRA_CFLAGS=-fno-pic M=$(PWD) modules 
	mv scanprocess.ko scanprocess-$(KVER).ko

modules:	main.c disk.c lime.h
	$(MAKE) -C /lib/modules/$(KVER)/build M=$(PWD) $@
	strip --strip-unneeded scanprocess.ko

modules_install:	modules
	$(MAKE) -C /lib/modules/$(KVER)/build M=$(PWD) $@

clean:
	rm -f *.o *.mod.c Module.symvers Module.markers modules.order \.*.o.cmd \.*.ko.cmd \.*.o.d
	rm -rf \.tmp_versions

distclean: mrproper
mrproper:	clean
	rm -f *.ko
