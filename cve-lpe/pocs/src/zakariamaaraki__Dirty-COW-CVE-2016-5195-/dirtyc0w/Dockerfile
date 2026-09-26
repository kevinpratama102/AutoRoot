FROM nginx:1.10.2

RUN useradd hacker -m

RUN apt-get update && \
    apt-get -y install gcc mono-mcs sudo

USER hacker

WORKDIR /home/hacker

ADD dirtyc0w.c dirtyc0w.c

RUN gcc -pthread dirtyc0w.c -o dirtyc0w

USER root

RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

CMD ["nginx", "-g", "daemon off;"]



