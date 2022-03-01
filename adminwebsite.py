# Python 3 server example
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
import time
from urllib.parse import unquote_plus
import json
import os
import elasticsearch
import datetime

hostName = "10.3.0.12"
serverPort = 8080

#hostName = 'localhost'
#serverPort = 80

log = "./log.txt"

ES_URL = os.environ.get('ES_URL')
if not ES_URL:
    print("ES_URL was missing")
    exit(1)
ELASTICSEARCH = elasticsearch.Elasticsearch(ES_URL)

class MyServer(SimpleHTTPRequestHandler):
    def do_GET(self):
        #print(self.path)
        #self.send_response(200)
        #self.send_header("Content-type", "text/html")
        #self.end_headers()
        #self.wfile.write(bytes("<html><head><title>Secure Area Login</title></head><body>", "utf-8"))
        #self.wfile.write(bytes(" <h1>Log in to Secure Area</h1> <form method='post' action='/'>", "utf-8"))
        #self.wfile.write(bytes("<b>Username:</b> <input name='username' type='text'/><br/>", "utf-8"))
        #self.wfile.write(bytes("<b>Password:</b> <input name='password' type='password'/><br/>", "utf-8"))
        #self.wfile.write(bytes("<input type='submit' name='submit'/>", "utf-8"))
        #self.wfile.write(bytes("</form>", "utf-8"))
        #self.wfile.write(bytes("</body></html>", "utf-8"))
        
        #test 
        #self.path = '/var/www/html/index.html'
        ip = self.client_address[0]
        port = self.client_address[1]
        time = datetime.datetime.now().isoformat()
        record = {
                "@timestamp": time,
                "action": "get",
                "fields": {
                    "ip": ip,
                    "port": port,
                    "url path": self.path,
                    }
                }
        ELASTICSEARCH.index(index="web-test", document=record)
        '''logfile = open(log, "a")
        logfile.write("\n")
        json.dump(record, logfile)
        logfile.close()
        '''
        #self.path = '/index.html'
        return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        #record information submitted in a log file, json
        #print error message or handle injection attacks here
        #self.send_response(200)
        #self.send_header("Content-type", "text/html")
        #self.end_headers()

        content_length = int(self.headers['Content-Length'])
        content = self.rfile.read(content_length)
        #print(content)
        #print(type(content))
        #print(str(content)[2:-1])
        test_decode = unquote_plus(str(content)[2:-1])
        #print(test_decode)
        #print(str(test_decode))
        results = test_decode.split('&')
        #print(results)
        uname = results[0][6:]
        passwd = results[1][4:]
        ip = self.client_address[0]
        #print(uname)
        #print(passwd)
        #print(ip)
        port = self.client_address[1]
        time = datetime.datetime.now().isoformat()
        headers = self.headers
        #print(headers)
       
        #print(headers['Host'])

        #print(dir(headers))
        #need to add header information
        header = {}
        for k in headers:
            header[k] = headers[k]

        sql_error_uname = check_sql(uname, uname, passwd)
        sql_error_passwd = check_sql(passwd, uname, passwd)
        sql = {
                "sql_injection": False,
                "username_injection": False,
                "password_injection": False,
                }
        sql_error = ''
        #sql injection in username
        if(sql_error_uname[0]):
            sql["sql_injection"] = True
            sql["username_injection"] = True
            if(sql_error_uname[1]!='user0318'):
                sql["username_specified"] = sql_error_uname[1]
            if(sql_error_uname[2]):
                sql["success"] = True
            else:
                sql["success"] = False
                sql["sql_error_sent"] = sql_error_uname[3]
                sql_error = sql_error_uname[3]
            sql["attempt"] = uname
        #sql injection in password
        if(sql_error_passwd[0]):
            sql["sql_injection"] = True
            sql["password_injection"] = True
            if(sql_error_passwd[2]):
                sql["success"] = True
            elif(not sql_error_uname[0]):
                sql["success"] = False
                sql_error = sql_error_passwd[3]
                sql["sql_error_sent"] = sql_error
            if(not sql_error_uname[0]):
                sql["username_specified"] = uname
            sql["attempt"] = passwd

        inj_attempt = check_parameter_injection(uname, passwd)


        record = {
                "@timestamp": time,
                "action": "post",
                "fields": {
                    "ip": ip,
                    "port": port,
                    "time": time,
                    "username": uname,
                    "password": passwd,
                    "sql": sql,
                    "parameter_injection": {"attempt": inj_attempt[0], "injection_string": inj_attempt[1]},
                    "headers": header,
                    }
                }
        ELASTICSEARCH.index(index="web-test", document=record)
        '''
        logfile = open(log, "a")
        logfile.write("\n")
        json.dump(record, logfile)
        logfile.close()
        '''
        os_commands = {
            "ls" : "/ls.html",
            "ls+-la": "/lsoutput.html",
            "pwd" : "/pwd.html",
        }
        if(passwd=='1'):
            self.path = '/onclicksubmit.html'
            SimpleHTTPRequestHandler.do_GET(self)
        elif(sql["sql_injection"]):
            self.path = '/onclicksubmit.html'
            SimpleHTTPRequestHandler.do_GET(self)
        '''
        elif inj_attempt[0]:
            # if injection attempt[0] is True
            # injection attempt[1] holds the injection string
                for command in os_commands.keys():
                    if command in inj_attempt[1]:
                        print("Debegging parameter injections: \n",inj_attempt,"\n", command,"\n", os_commands[command])
                        self.path = os_commands[command]
                        SimpleHTTPRequestHandler.do_GET(self)
                else:
                        self.path = '/permissiondenied.html'
                        SimpleHTTPRequestHandler.do_GET(self)
        '''
        self.path = '/loginfailed.html'
        SimpleHTTPRequestHandler.do_GET(self)

def check_parameter_injection(uname, passwd):
    injection_string = ''
    list_spl_chars = ['&', ';', '0x0a', '\n', '&&', '|', '||']
    for char in list_spl_chars:
        if char in uname:
            attempt = True
            new_str = uname.split(char)
            injection_string = new_str[1]
            break
        elif char in passwd:
            attempt = True
            new_str = passwd.split(char)
            injection_string = new_str[1]
            break
        else:
            attempt = False
    return [attempt, injection_string]

def parse_sql(command):
    #return format: [success T/F, command if T or reason if F]
    #print('command: ',command)
    command = command.upper()
    #command = command.replace('+', ' ')
    command_list = command.split(' ')
    #print('command list: ', command_list)
    permissions_statements = ['UPDATE','DELETE','DROP','CREATE','ALTER','UNION','SELECT']
    for statement in permissions_statements:
        if(statement in command_list):
            return [False, statement]
    print("parse sql(",command,")")
    if (command.strip() == ';' or command.strip()==''):
        return [True, command]
    #check logic
    if('OR' in command_list):
        print(command_list)
        before = ''
        after = ''
        for i in range(len(command_list)):
            if(command_list[i] == '=' and i<len(command_list)):
                after = command[i+1]
                if(before!='' and (before==after or before==after+"'")):
                    return [True, 'or']
            before = command_list[i]
        for i in command_list:
            if('=' in i):
                equation = i
                equation = equation.split('=')
                if(equation[0]==equation[1] or equation[0]==equation[1]+"'"):
                    return [True, 'or']
    return [False, command]

def check_sql(string, uname, passwd):
    #return format: [sql_inj T/F, username attempted, success T/F if applicable, error code if applicable or sql code injected]
    #sql query:
    #SELECT * FROM users WHERE username = uname AND password = psw
    #normal entry:
    #SELECT * FROM users WHERE username = 'caitlin' AND password = '1'
    #injection attempt:
    #SELECT * FROM users WHERE username = 'caitlin' AND password = 'password' OR '1' = '1'
    query = "SELECT * FROM users WHERE username =  AND password = "
    misspell_error = 'Syntax error in SQL statement "SELECT * FROM users WHERE username = ' + uname + ' AND password = ' + passwd + ';"'
    quotes_error = 'Syntax error at or near ";" Position: ' + str(len(query)+len(uname)+len(passwd))
    permissions_error = 'Error: user does not have '
    permissions_error_2 = ' permissions'
    generic_error = 'Syntax error in SQL statement'

    #print("string:", string)
    #print("passwd:", passwd)

    #remove up until first single quote
    string_list = string.split("'",1)
    #passwd_list = passwd.split("'",1)
    string_1 = string_list[0] #this is the username attempted
    #password = passwd_list[0]
    #print(username, password)
    #print(type(username), type(password))
    #print(uname_list, passwd_list)
    if (len(string_list)==1):
        #no single quotes
        return [False, string_1]
    #only keep string before comments
    comments = ['--','#','/*']
    string_comment = False
    for comment in comments:
        if(comment in string_list[1]):
            #check for comments after first single quote
            string_comment = True
            string_list[1] = string_list[1].split(comment)[0] #this keeps everything before the comment
    #remove after last single quote if not commented
    if (len(string_list)>1 and not string_comment):
        string_r = string_list[1][::-1]
        string_list = string_r.split("'",1)
    elif (not string_comment):
        string_list = []
    #if (len(passwd_list)>1 and not passwd_comment):
    #    passwd_r = passwd_list[1][::-1]
    #    passwd_list = passwd_r.split("'",1)
    #elif (not passwd_comment):
    #    passwd_list = []
    #print(uname_list, passwd_list)
    if (len(string_list)==1):
        #one single quote, throw error
        return [True, string_1, False, quotes_error]
    #isolate sql command and parse
    if (len(string_list)>1):
        if(not string_comment):
            string_command = string_list[1][::-1]
        else:
            string_command = string_list[1]
        #print(string_command)
        string_results = parse_sql(string_command)

        #check for permissions error
        permissions_statements = ['SELECT','UPDATE','DELETE','DROP','CREATE','ALTER','UNION']
        if(string_results[0]==False and string_results[1] in permissions_statements):
            return [True, string_1, False, permissions_error+string_results[1]+permissions_error_2]
        elif(string_results[0]==True):
            if(string_results[1]=='or'):
            #username not specified
                return [True, "user0318", True, string_command]
            else:
                return [True, string_1, True, string_command]
        print(string_results)

    return [True, string_1, False, generic_error]

def main():
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    #BaseHTTPRequestHandler.server_version = ""
    #BaseHTTPRequestHandler.sys_version = "Apache httpd 2.4.18"
    SimpleHTTPRequestHandler.server_version = "Apache/2.2.3"
    BaseHTTPRequestHandler.sys_version = "Ubuntu"

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")

if __name__ == "__main__":
    main()