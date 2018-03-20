import ConfigParser
import base64
import sys
import socket
import select
import os
import hashlib
import signal
import title
from random import choice
from time import sleep
from col import Colours as C
from col import Colours_list as Rcolour
from Crypto.Cipher import AES

myColour = choice(Rcolour())
os.system("clear")

def sigint_handler(signum, frame):
    print('\n user interrupt ! shutting down')
    print("quitting session\n\n")
    sys.exit()	
signal.signal(signal.SIGINT, sigint_handler)

def hasher(key):
	hash_object = hashlib.sha512(key)
	hexd = hash_object.hexdigest()
	hash_object = hashlib.md5(hexd)
	hex_dig = hash_object.hexdigest()
	return hex_dig

def encrypt(secret,data):
	BLOCK_SIZE = 32
	PADDING = '{'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	cipher = AES.new(secret)
	encoded = EncodeAES(cipher, data)
	return encoded

def decrypt(secret,data):
	BLOCK_SIZE = 32
	PADDING = '{'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	cipher = AES.new(secret)
	decoded = DecodeAES(cipher, data)
	return decoded


def chat_client():
    if(len(sys.argv) < 5) :
        print('Usage : python cia_chat.py <hostname> <port> <password> <nick_name>')
        sys.exit()
    host = sys.argv[1]
    port = int(sys.argv[2])
    key = sys.argv[3]
    key = hasher(key)	
    uname = sys.argv[4]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try :
        s.connect((host, port))
    except :
        print("{}Unable to connect{}".format(C.red, C.end))
        sys.exit()
    title.Title()
    print("Username set to {}; your colour is [{}colour{}]".format(uname, myColour, C.end))
    sys.stdout.write("{}\nMe >> {}".format(C.red, C.end)); sys.stdout.flush()
    while 1:
        socket_list = [sys.stdin, s]
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
        for sock in read_sockets:
            if sock == s:
                data = sock.recv(4096)
                if not data :
                    print("{}\nDisconnected from chat server{}".format(C.red, C.end))
                    sys.exit()
                else :
                    data = decrypt(key,data)
                    sys.stdout.write(data)
                    sys.stdout.write("{}\nMe >> {}".format(C.red, C.end)); sys.stdout.flush()
            else :
                msg = sys.stdin.readline()
                msg = "{}<{}> {}{}".format(myColour, uname, msg, C.end)
                msg = encrypt(key,msg)
                s.send(msg)
                sys.stdout.write("{}\nMe >> {}".format(C.red, C.end)); sys.stdout.flush()

if __name__ == "__main__":
    sys.exit(chat_client())
