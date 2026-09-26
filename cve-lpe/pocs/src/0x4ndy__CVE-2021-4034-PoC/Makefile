CFLAGS=-Wall
TRUE=$(shell which true)

.PHONY: all
all: build pklib.so pk gconvmod gconvpath package

.PHONY: clean
clean:
	rm -rf build 
	rm -f pk.tgz

build:
	mkdir -p build/pk

gconvpath:
	mkdir -p build/pk/GCONV_PATH=.
	cp -f $(TRUE) build/pk/GCONV_PATH=./pklib.so:.

gconvmod:
	echo "module UTF-8// PKLIB// pklib 1" > build/pk/gconv-modules

pklib.so: src/pklib.c
	$(CC) $(CFLAGS) --shared -fPIC -o build/pk/$@ $<

pk: src/pk.c
	$(CC) $(CFLAGS) -o build/pk/$@ $<

package:
	cd build && tar czvf ../pk.tgz pk && cd - 
