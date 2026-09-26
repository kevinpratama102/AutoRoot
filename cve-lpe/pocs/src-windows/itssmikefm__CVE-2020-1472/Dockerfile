FROM python:slim

RUN apt update
RUN apt install -y git

RUN git clone https://github.com/SecureAuthCorp/impacket.git
WORKDIR impacket
RUN pip install .
RUN python3 setup.py install

RUN git clone https://github.com/itssmikefm/CVE-2020-1472.git
WORKDIR CVE-2020-1472
RUN cp ../examples/secretsdump.py .
RUN cp ../examples/wmiexec.py .
# CMD [ "./cve-2020-1472-exploit.py" ]
ENTRYPOINT ["python"]
