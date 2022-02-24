# Python 3 server example
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
import time
from urllib.parse import unquote
import json

hostName = "10.3.0.12"
serverPort = 8080

#hostName = 'localhost'
#serverPort = 80

log = "./log.txt"

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

        record = {
                "action": "get",
                "fields": {
                    "ip": ip,
                    "port": port,
                    "url path": self.path,
                    }
                }
        logfile = open(log, "a")
        logfile.write("\n")
        json.dump(record, logfile)
        logfile.close()
        
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
        test_decode = unquote(content)
        #print(test_decode)
        results = test_decode.split('&')
        #print(results)
        uname = results[0][6:]
        passwd = results[1][4:]
        ip = self.client_address[0]
        #print(uname)
        #print(passwd)
        #print(ip)
        port = self.client_address[1]
        #print(dir(self))
        time = self.date_time_string()
        headers = self.headers
        #print(headers)
       
        #print(headers['Host'])

        #print(dir(headers))
        #h = str(headers)
        #print(h)
        #print(headers.keys)
        #need to add header information
        header = {}
        for k in headers:
            header[k] = headers[k]
        #print(headers)

        sql_error_uname = check_sql(uname, uname, passwd)
        sql_error_passwd = check_sql(passwd, uname, passwd)
        print('sql uname',sql_error_uname)
        if(sql_error_uname!='no' or sql_error_passwd!='no'):
            sql = True
            print(sql_error_uname, sql_error_passwd)
        else:
            sql = False

        record = {
                "action": "post",
                "fields": {
                    "ip": ip,
                    "port": port,
                    "time": time,
                    "username": uname,
                    "password": passwd,
                    "sql injection": sql,
                    "headers": header,
                    }
                }
        logfile = open(log, "a")
        logfile.write("\n")
        json.dump(record, logfile)
        logfile.close()


        if(passwd=='1'):
            self.path = '/onclicksubmit.html'
            return SimpleHTTPRequestHandler.do_GET(self)
        elif("ls" in passwd):
            self.path = '/lsoutput.html'
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.path = '/loginfailed.html'
            SimpleHTTPRequestHandler.do_GET(self)

def parse_sql(command):
    #if(';' in command):
    #    return 'multiple_commands'
    #print('command: ',command)
    command = command.upper()
    command = command.replace('+', ' ')
    command_list = command.split(' ')
    #print('command list: ', command_list)
    permissions_statements = ['SELECT','UPDATE','DELETE','DROP','CREATE','ALTER']
    for statement in permissions_statements:
        if(statement in command_list):
            return statement
    
    return 'test'

def check_sql(string, uname, passwd):
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
    #multiple_commands_error = ''
    generic_error = 'Syntax error in SQL statement'

    #print("string:", string)
    #print("passwd:", passwd)

    #remove up until first single quote
    string_list = string.split("'",1)
    #passwd_list = passwd.split("'",1)
    string_1 = string_list[0]
    #password = passwd_list[0]
    #print(username, password)
    #print(type(username), type(password))
    #print(uname_list, passwd_list)
    if (len(string_list)==1):
        #no single quotes
        return "no"
    #only keep string before comments
    comments = ['--','#','/*']
    string_comment = False
    #passwd_comment = False
    for comment in comments:
        if(comment in string_list[1]):
            string_comment = True
            string_list[1] = string_list[1].split(comment)[0]
        #if(comment in passwd_list[1]);
        #    passwd_comment = True
        #    passwd_list[1] = passwd_list[1].split(comment)[0]
    #remove after last single quote if not commented
    if (len(string_list)>1 and not string_comment):
        string_r = string_list[1][::-1]
        string_list = string_r.split("'",1)
    elif (not string_comment):
        uname_list = []
    #if (len(passwd_list)>1 and not passwd_comment):
    #    passwd_r = passwd_list[1][::-1]
    #    passwd_list = passwd_r.split("'",1)
    #elif (not passwd_comment):
    #    passwd_list = []
    #print(uname_list, passwd_list)
    if (len(string_list)==1):
        #one single quote, throw error
        return quotes_error
    #isolate sql command and parse
    if (len(string_list)>1):
        #string_command = string_list[1][::-1]
        string_command = string_list[1]
        #print(string_command)
        string_results = parse_sql(string_command)
    #if(len(passwd_list)>1):
    #    passwd_command = passwd_list[1][::-1]
    #    passwd_results = parse_sql(passwd_command)
    #    print(passwd_command)
    #check for single quotes
    #if (uname.count("'")%2!=0 or passwd.count("'")%2!=0):
    #    return quotes_error

    #check double quotes
    #if (uname.count('"')%2!=0 or passwd.count('"')%2!=0):
    #    return quotes_error
    
        permissions_statements = ['SELECT','UPDATE','DELETE','DROP','CREATE','ALTER']
        if(string_results in permissions_statements):
            return permissions_error+string_results+permissions_error_2
        else:
            print(string_results)
    return 'no'

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

