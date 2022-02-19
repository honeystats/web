# Python 3 server example
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
import time
from urllib.parse import unquote

hostName = "10.3.0.12"
serverPort = 80

class MyServer(SimpleHTTPRequestHandler):
    def do_GET(self):
        print(self.path)
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
        return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        #record information submitted in a log file, json
        #print error message or handle injection attacks here
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

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
        print(uname)
        print(passwd)
        print(ip)
        port = self.client_address[1]
        #print(dir(self))
        time = self.date_time_string()
        headers = self.headers
        print(headers)


def main():
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    #BaseHTTPRequestHandler.server_version = ""
    #BaseHTTPRequestHandler.sys_version = "Apache httpd 2.4.18"
    BaseHTTPRequestHandler.server_version = "Apache/2.2.3"
    BaseHTTPRequestHandler.sys_version = "Ubuntu"

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")

if __name__ == "__main__":
    main()

