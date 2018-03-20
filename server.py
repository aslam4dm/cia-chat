import configparser
import base64
import sys
import socket
import select
import os
import hashlib
import signal
import col
import title
from time import sleep
from Crypto.Cipher import AES

os.system("clear")
def banner():
		title.Title()

def banner_info(addr, port, server_status):
	cia = "Produced by the CIA-Project"
	for char in cia:
		sleep(0.03)
		sys.stdout.write(char)
		sys.stdout.flush() 
	sleep(0.4)
	info = "\nserver loading..."
	for char in info:
		sleep(0.06)
		sys.stdout.write(char)
		sys.stdout.flush() 
	sleep(2.5)
	if server_status == True:
		more_info = "\nServer created [address: {}][port: {}]\n".format(addr, port)
		for char in more_info:
			sleep(0.05)
			sys.stdout.write(char)
			sys.stdout.flush() 
		sleep(2)
	else:
		print("\nServer error")

# deals with ctrl-C interrupts
def sigint_handler(signum, frame):
    print ('user interrupt ! shutting down')
    print ("server shutting down\n\n")
    sys.exit()	 
signal.signal(signal.SIGINT, sigint_handler)

def hasher(key):
	hash_object = hashlib.sha512(key.encode('utf-8'))
	hexd = hash_object.hexdigest()
	hash_object = hashlib.md5(hexd.encode('utf-8'))
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


config = configparser.RawConfigParser()   
config.read(r'cia-chat.conf')
HOST = config.get('config', 'HOST')
PORT = int(config.get('config', 'PORT'))
PASSWORD = config.get('config', 'PASSWORD')
VIEW = str(config.get('config', 'VIEW'))
key = hasher(PASSWORD)
SOCKET_LIST = []
RECV_BUFFER = 4096

def chat_client():	
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	
	server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)	
	server_socket.bind((HOST, PORT))	
	server_socket.listen(10)	
	SOCKET_LIST.append(server_socket)
	banner_info(HOST, str(PORT), True)
	while 1:
	    ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
	    for sock in ready_to_read:
	        if sock == server_socket:
	            sockfd, addr = server_socket.accept()
	            SOCKET_LIST.append(sockfd)
	            print("user {} connected".format(addr))
	            broadcast(server_socket, sockfd, encrypt(key,"\n{} entered our chatting room\n".format(addr)))
	        else:
	            try:
	                data = sock.recv(RECV_BUFFER)
	                data = decrypt(key,data)
	                if data:
	                    broadcast(server_socket, sock,encrypt(key,"\r" + data))
	                    if VIEW == '1':
	                      print(data)
	                else:
	                    if sock in SOCKET_LIST:
	                        SOCKET_LIST.remove(sock)
	                    broadcast(server_socket, sock,encrypt(key,"user {}, is offline\n".format(addr)))
	            except:
	                broadcast(server_socket, sock, "user {}, is offline\n".format(addr))
	                continue
	server_socket.close()

def broadcast (server_socket, sock, message):
    for socket in SOCKET_LIST:
        if socket != server_socket and socket != sock :
            try :
                socket.send(message)
            except :
                socket.close()
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)


if  __name__ == "__main__": 
	chat_client()
