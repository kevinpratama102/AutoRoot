FROM ubuntu

ENV DEBIAN_FRONTEND=noninteractive

RUN adduser pwnkit
RUN apt update && apt install -y build-essential

COPY blasty-vs-pkexec.c .
RUN gcc -o blasty blasty-vs-pkexec.c
RUN chmod +x blasty
RUN mv blasty /home/pwnkit/

RUN apt install -y --no-install-recommends policykit-1=0.105-26ubuntu1 libpolkit-agent-1-0=0.105-26ubuntu1 libpolkit-gobject-1-0=0.105-26ubuntu1

CMD ["su", "-", "pwnkit"]
