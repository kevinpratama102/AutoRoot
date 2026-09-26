FROM debian:jessie

LABEL author="t0kx (t0kx@protonmail.ch)"
LABEL maintainer="cved (cved@protonmail.com)"

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update \
    && apt-get -y install \
    wget \
    build-essential \
    && apt-get autoremove \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN wget https://www.sudo.ws/dist/sudo-1.8.13.tar.gz -O /tmp/sudo.tar.gz \
    && tar xfz /tmp/sudo.tar.gz -C /tmp/ \
    && cd /tmp/sudo-1.8.13 \
    && ./configure \
    && make \
    && make install \
    && rm -rf /tmp/sudo*

RUN useradd -d /home/cved -s /bin/bash -ms /bin/bash cved \
    && echo 'cved ALL=NOPASSWD: sudoedit /home/*/*/file.txt' >> /etc/sudoers
