all : exploit shared_object

exploit:
	gcc baron_samedit.c -o baron_samedit

shared_object:
	gcc -shared -o libnss_HACK/TEH_WORLD.so.2 -fPIC libnss_HACK/TEH_WORLD.c
