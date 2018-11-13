from Crypto.Util.number import *
import SocketServer
import string
import hashlib
import random
import requests
import json
from flag import *

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class RSATCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        self.request.sendall("Welcome to flag getting system\ngive me your token > ")
        token = self.request.recv(1024).strip()
        if not verify(token):
            self.request.sendall("token error\n")
        else:
            p = getStrongPrime(1024)
            q = getStrongPrime(1024)
            n = p * q
            e = 5
            nbits = size(n)
            xorbits = nbits // (2 * e * e)
            m1 = getRandomNBitInteger(nbits)
            m2 = m1 ^ getRandomNBitInteger(xorbits)
            c1 = pow(m1, e, n)
            c2 = pow(m2, e, n)

            self.request.sendall("n=" + str(n) + "\n")
            self.request.sendall("c1=" + str(c1) + "\n")
            self.request.sendall("c2=" + str(c2) + "\n")

            self.request.sendall("now give me you answer\n")
            ans1 = self.request.recv(2048).strip()
            ans2 = self.request.recv(2048).strip()

            if str(ans1) == str(m1) and str(ans2) == str(m2):
                self.request.sendall(FLAG)
            else:
                self.request.sendall("wrong answer\n")

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 10086
    server = ThreadedTCPServer((HOST, PORT), RSATCPHandler)
    server.serve_forever()