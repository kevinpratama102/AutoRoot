.PHONY: all clean present

TARGET := Debugging_Dirty_Pipe_CVE-2022-0847.pdf

all: $(TARGET)

clean:
	rm -f $(TARGET)

%.pdf %.tex: %.md
	podman run --rm --init -v "$$PWD:/home/marp/app/" -e LANG=$LANG docker.io/marpteam/marp-cli $^ --html --pdf --allow-local-files -o - > $@

present: $(TARGET)
	pdfpc --windowed=both $^
