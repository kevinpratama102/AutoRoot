FROM kalilinux/kali-rolling:latest
RUN apt update

# dev tools
RUN apt-get install -y gcc make

# polkit
RUN apt-get install -y libpolkit-gobject-1-0
RUN apt-get install -y libpolkit-agent-1-0
RUN apt-get install -y policykit-1

RUN useradd -ms /bin/bash hoangnch
USER hoangnch

RUN mkdir /home/hoangnch/pwnkit
COPY conversion-mod.c Makefile pwnkit.c /home/hoangnch/pwnkit/
WORKDIR /home/hoangnch/pwnkit
