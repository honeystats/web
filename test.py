# Python 3 server example
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
import time
from urllib.parse import unquote
import json

hostName = "10.3.0.12"
serverPort = 8080

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

        sql_error = check_sql(uname, passwd)
        if(sql_error!='no'):
            sql = True
            print(sql_error)
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

def check_sql(uname, passwd):
    #sql query:
    #SELECT * FROM users WHERE username = uname AND password = psw
    #normal entry:
    #SELECT * FROM users WHERE username = 'caitlin' AND password = '1'
    #injection attempt:
    #SELECT * FROM users WHERE username = 'caitlin' AND password = 'password' OR 1=1 OR 'password' = '1'
    query = "SELECT * FROM users WHERE username =  AND password = "
    misspell_error = 'Syntax error in SQL statement "SELECT * FROM users WHERE username = ' + uname + ' AND password = ' + passwd + ';"'
    quotes_error = 'Syntax error at or near ";" Position: ' + str(len(query)+len(uname)+len(passwd))
    generic_error = 'Syntax error in SQL statement'


    #check for single quotes
    if (uname.count("'")%2!=0 or passwd.count("'")%2!=0):
        return quotes_error

    #check double quotes
    if (uname.count('"')%2!=0 or passwd.count('"')%2!=0):
        return quotes_error


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

