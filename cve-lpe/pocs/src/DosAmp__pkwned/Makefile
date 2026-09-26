ALL = gconv/gconv-modules gconv/pwnie.so example-victim pkwned gconv-fuse
EVERYTHING = $(ALL) mypath.h

override CFLAGS += -std=c99

all: $(ALL)

gconv/gconv-modules: constants.h
	sed 's/%CHARSET%/'"$$(awk '$$2=="TROJAN_CHARSET"{gsub(/"/,"",$$3);print $$3}' constants.h)/" gconv/gconv-modules.tpl > gconv/gconv-modules

gconv/pwnie.so: gconv-pwnie.o
	$(CC) -o $@ -shared $(LDFLAGS) $<

gconv-pwnie.o: constants.h mypath.h gconv-pwnie.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -fPIC gconv-pwnie.c

mypath.h:
	./mypath.sh > mypath.h

pkwned: constants.h pkwned.c
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) pkwned.c

example-victim: constants.h example-victim.c
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) example-victim.c

gconv-fuse: constants.h gconv-fuse.c
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) gconv-fuse.c $$(pkg-config fuse --cflags --libs)

clean:
	rm -f *.o $(EVERYTHING) a.out

.PHONY: all clean
