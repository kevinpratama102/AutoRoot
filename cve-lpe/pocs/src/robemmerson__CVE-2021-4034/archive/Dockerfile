FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive

RUN apt -q update && \
    apt -q -y install gcc policykit-1

COPY pkexec /usr/bin/pkexec

RUN chmod 4755 /usr/bin/pkexec && \
    useradd -m -s /bin/bash low && \
    mkdir -p /opt/test && \
    chown low:low /opt/test && \
    chmod 777 /opt/test

WORKDIR /opt/test

USER low

COPY cve-2021-4034-poc.c /opt/test/cve-2021-4034-poc.c

RUN gcc cve-2021-4034-poc.c -o cve-2021-4034-poc && \
    id && \
    ls -la
