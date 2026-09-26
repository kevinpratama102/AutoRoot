






.phony: exp test



exp:
	sudo bear -- gcc -I ./work/include -L ./work -static -o temp_mount/exp work/exp.c -l:liburing.a
test:
	sudo bear -- gcc -I ./work/include -L ./work -static -o temp_mount/test work/test.c -l:liburing.a
