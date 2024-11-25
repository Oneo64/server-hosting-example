"""
- Whitelisting and blacklisting, with manual whitelist toggle
- Malicious IP detection
- Basic anti-injection/exploit
- Random port number, acts as password
"""

import os
import random
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# SETTINGS
root = "C://Users/User/LocalServer"
whitelist_on = False
whitelist = [
    "127.0.0.1"
]
blacklist = []
banned = []

hostName = "localhost"
serverPort = 55555


class SafeServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.connection.getsockname()[0] in banned:
            return

        if "%7B" in self.path or "%22" in self.path:
            self.connection.shutdown(socket.SHUT_RDWR)
            print("Malicious activity detected: " + str(self.connection.getsockname()[0]))
            banned.append(self.connection.getsockname()[0])
            print("Blocked: " + self.connection.getsockname()[0])
            return

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        path = self.path

        if not path.endswith(".ttf"):
            if path == "/":
                path = "index.html"

            if os.path.isfile(root + path):
                f = open(root + path, "r")
            elif os.path.isfile(root + "/" + path):
                f = open(root + "/" + path, "r")
            else:
                f = open(root + "/not_found.html", "r")

            contents = f.read()
            contents = "<style>\n" + open(root + "/Styles/style.css", "r").read() + "\n</style>" + contents

            self.wfile.write(bytes(contents, encoding="utf8"))
            f.close()


class Terminal:
    def __init__(self, server):
        print("Terminal initiated.")

        listener = threading.Thread(target=self.listen, args=(server,))
        listener.start()

    def listen(self, server):
        global whitelist_on

        while True:
            raw_cmd = self.get()
            cmd = raw_cmd.split(" ")
            message = ""
            passed = False

            if len(cmd) == 1:
                if cmd[0] == "help":
                    print("======== Help page ========")
                    print()
                    print("wl on/off  - toggle whitelist")
                    print("wl         - view whitelist")
                    print("wl <ip>    - add/remove ip in whitelist")
                    print()
                    print("bl         - view blacklist")
                    print("bl <ip>    - add/remove ip in blacklist")
                    print()
                    print("banlist    - view ban list. these are clients that tried to malicious things.")
                    print("unban <ip> - forgives a client from the ban list")

                    passed = True

                if cmd[0] == "bl":
                    message = "Blacklist: " + str(blacklist)
                    passed = True

                if cmd[0] == "wl":
                    message = "Whitelist: " + str(whitelist)
                    passed = True

                if cmd[0] == "banlist":
                    message = "Ban list: " + str(banned)
                    passed = True

            if len(cmd) == 2:
                if cmd[0] == "bl":
                    if cmd[1] in blacklist:
                        message = "Un-blacklisted IP."
                        blacklist.remove(cmd[1])
                    else:
                        message = "Blacklisted IP."
                        blacklist.append(cmd[1])

                    passed = True

                if cmd[0] == "unban":
                    if cmd[1] in banned:
                        message = "Released IP from ban list."
                        banned.remove(cmd[1])
                    else:
                        message = "No IP was found."

                    passed = True

                if cmd[0] == "wl":
                    if cmd[1] == "on":
                        message = "Whitelist on."
                        whitelist_on = True
                    elif cmd[1] == "off":
                        message = "Whitelist off."
                        whitelist_on = False
                    elif cmd[1] in whitelist:
                        message = "Un-whitelisted IP."
                        whitelist.remove(cmd[1])
                    else:
                        message = "Whitelisted IP."
                        whitelist.append(cmd[1])

                    passed = True

            if message == "" and not passed:
                message = "Command unrecognised."

            if not passed or message != "":
                print(message)

    def get(self):
        return input()


if __name__ == "__main__":
    print("~~~~~~~~~~ Neo's Safe Server ~~~~~~~~~~")
    print("Server name:  http://%s:%s" % (hostName, serverPort))
    print("Last updated: 2023 june 29")
    print()
    print("Type help to show list of commands.")

    webServer = HTTPServer((hostName, serverPort), SafeServer)
    webServer.request_queue_size = 8

    terminal = Terminal(webServer)

    def verify_request(request, client_address):
        """
        This is extra security. It will remove access to any suspicious IP addresses.
        """

        if client_address[0] in banned:
            return False

        message = ""
        granted = True

        if whitelist_on and len(whitelist) > 0 and not client_address[0] in whitelist:
            message = "Uninvited IP address."
            granted = False

        if len(blacklist) > 0 and client_address[0] in blacklist:
            message = "Unwanted IP address."
            granted = False

        for i in client_address[0]:
            if not i.isdigit() and i != "." and i != ":":
                message = "Invalid IP address detected."
                granted = False
                break

        if len(client_address[0]) > 64:
            message = "Invalid IP address detected."
            granted = False

        if not granted:
            print("Access denied: " + message + " (" + client_address[0] + ")")
            banned.append(client_address[0])

        return granted

    webServer.verify_request = verify_request

    try:
        webServer.serve_forever()
    except KeyboardInterrupt or SystemExit:
        pass

    webServer.server_close()
    print("Server stopped.")
