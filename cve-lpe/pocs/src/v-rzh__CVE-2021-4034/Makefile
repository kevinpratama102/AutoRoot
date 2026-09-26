CC=gcc
LIBNAME=FRUITLOOPS
LIB=$(LIBNAME).so
LIB_SRC=lib.c
LD_FLAGS=-shared -fPIC

CFLAGS=-D $(LIBNAME)
EXPL_SRC=exploit.c
EXPL=exploit

.PHONY: all clean

all: $(EXPL) $(LIB)

$(EXPL): $(EXPL_SRC)
	$(CC) $(CFLAGS) -o $@ $^

$(LIB): $(LIB_SRC)
	$(CC) -o $@ $^ $(LD_FLAGS)

clean:
	-rm $(EXPL)
	-rm $(LIB)
