import requests
import re
requests.packages.urllib3.disable_warnings()
from colorama import Fore, Back, Style
import argparse


url_template = "https://{systemip}/webui/logoutconfirm.html?logon_hash=1"

print(f"""
   ___ ___ ___  ___ ___     ___ __ ___ ____   ___ __  _ ___ ___ 
  / __|_ _/ __|/ __/ _ \ __|_  )  \_  )__ /__|_  )  \/ / _ ( _ )
 | (__ | |\__ \ (_| (_) |___/ / () / / |_ \___/ / () | \_, / _ |
  \___|___|___/\___\___/   /___\__/___|___/  /___\__/|_|/_/\___/ @{Fore.RED}system00security{Style.RESET_ALL}
  - Checker for CVE-2023-20198 {Fore.RED}[https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z]{Style.RESET_ALL}                                                              
""")




def is_hexadecimal_string(s):
    return bool(re.match(r'^[0-9a-fA-F]+$', s))


def poc(ip):
    url =f"https://{ip}/webui/logoutconfirm.html?logon_hash=1"
    try:
        print(f"Checking [RADICTED] for CVE-2023-20198")
        response = requests.post(url, verify=False, timeout=10)
        if response.status_code == 200:
            response_text = response.text
            if is_hexadecimal_string(response_text):
                print(f"[=]{Fore.RED} [RADICTED] {Style.RESET_ALL} is Possibly vulnerable to CVE-2023-20198, Implant found {Fore.RED} {response_text} {Style.RESET_ALL}")
            else:
                print(f"[+]{Fore.GREEN} [RADICTED] {Style.RESET_ALL} is not vulnerable to CVE-2023-20198")
        else:
            print(f"[-]{Fore.YELLOW} [RADICTED] {Style.RESET_ALL} Request failed with status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[-]{Fore.YELLOW} [RADICTED] {Style.RESET_ALL} Connection Failed , Unable to connect to {ip} due to {str(e)}")


parser = argparse.ArgumentParser(description='Cisco IOS-XE WebUI Privilege Escalation Checker')
parser.add_argument('-i', '--ip', help='IP Address of the target')
parser.add_argument('-f', '--file', help='File containing list of IPs', required=False)
args = parser.parse_args()

if args.ip:
    poc(args.ip)
elif args.file:
    with open(args.file, 'r') as f:
        for line in f:
            poc(line.strip())
else:
    print("[-] No arguments provided, use -h or --help for help")
