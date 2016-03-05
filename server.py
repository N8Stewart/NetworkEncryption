#!/usr/local/python-3.2.3/bin/python3.2

# Nate Stewart
# 02/27/16
# Network Encryption Client

# Import the functionality for socket connections
import socket, select
# needed to assess if the connection to the server was refused
from socket import error as socket_error
# import needed functions from sys such as sys.exit() and sys.argv()
import sys
# import needed functions from os to create 'recv' directory
import os
# check the error number of invalid connection 
import errno
# Import constants file
import constants
# Grab a random number generator for the uid's
from random import randint

# Class to store important information about the clients connected to the server
class client(object) :
    def __init__(self, uid, name, address, publicKey) :
        self.uid = uid
        self.name = name
        self.address = address
        self.publicKey = publicKey

# Broadcast message to all connections
def broadcast (message) :
    # for every connection in connections
    for sock in CONNECTIONS :
        if sock != server_socket :
            try :
                sock.send(message)
            except :
                # connection broken(?)
                sock.close()
                del CLIENTS[CONNECTIONS.index(sock)]
                CONNECTIONS.remove(sock)

# Pack the flag, uid, and message inside a packet. Return this byte object to the caller to be sent across the network
# Encrypt the message only after the user has supplied their public key
def pack(flag, uid, message) :
    if flag == constants.FLAG_CONNECT or flag == constants.FLAG_DISCONNECT :
        packet = b''.join([flag.to_bytes(1, byteorder='big'),
                uid.encode()])
    elif flag == constants.FLAG_KEY_XCG or flag == constants.FLAG_UID :
        packet = b''.join([flag.to_bytes(1, byteorder='big'),
                message.encode()])
    elif flag == constants.FLAG_MESSAGE :
        packet = b''.join([flag.to_bytes(1, byteorder='big'),
                uid.encode(),
                message.encode()])
    else :
        raise ValueError('Cannot pack message. Invalid flag: ' + str(flag))
    return packet

# Unpack the byte object retrieved from the socket. Analyze the flag and perform a different action depending on what it is
def unpack(conn, packet) :
    flag = int.from_bytes(packet[:1], byteorder='big')
    numBytes = len(packet)
    message = packet[1:numBytes-1].decode()
    # Grab the user information of whoever sent the packet
    client = CLIENTS[CONNECTIONS.index(conn)]
    if flag == constants.FLAG_KEY_XCG : # Send the symmetric key to the user
        packet = b''.join([flag.to_bytes(1, byteorder='big'), message.encode()])
        # Store users public key and send the symmetric key and the user's unique id
        client.publicKey = message
        conn.send(pack(constants.FLAG_KEY_XCG, None, SYM_KEY))
        conn.send(pack(constants.FLAG_UID, None, client.uid))
        broadcast(pack(constants.FLAG_CONNECT, client.uid, None))
    elif flag == constants.FLAG_MESSAGE :
        uid = message[:constants.UID_LENGTH-1]
        message = packet[constants.UID_LENGTH:len(message)-1]
        sys.stdout.write("\r" + '<' + uid + '> ' + message)
        broadcast(pack(constants.FLAG_MESSAGE, uid, message))
    elif flag == constants.FLAG_DISCONNECT :
        uid = message
        sys.stdout.write("\r" + '<' + uid + '> disconnected')
        del CLIENTS[CONNECTIONS.index(conn)]
        CONNECTIONS.remove(conn)
        broadcast(pack(FLAG_DISCONNECT, uid, None))
    else :
        raise ValueError('Cannot unpack packet. Packet may have been corrupted. Invalid flag: ' + str(flag))

if __name__ != "__main__" :
    print ("Server cannot be embeded.")
    sys.exit(1)

# A list of the connections with the server
CONNECTIONS = []
# A list of the clients currently connected to the server, indexed to match the read_connections
CLIENTS = []
# The symmetric key generated every time the server opens up
SYM_KEY = "1234567890"

# wrap interrupt detection
try :
    # open a socket and begin listening on HOST:PORT
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((constants.HOST, constants.DEFAULT_PORT))
    # Let user know what host and port combination the socket is listening on
    print ("Listening on " + socket.gethostname() + " on port " + str(constants.DEFAULT_PORT))
    
    # Allow 16 incoming connections 
    server_socket.listen(16)
    CONNECTIONS.append(server_socket)
    CLIENTS.append(1) # server_socket is the exception.

    # Continuously be reading sockets for incoming messages
    while True :
        # get sockets which are ready to be read
        sck_read,sck_write,sck_err = select.select(CONNECTIONS,[],[])
        for sock in sck_read :
            # new connection
            if sock == server_socket :
                # Handle the case in which there is a new connection recieved through server_socket
                newSock, newAddr = server_socket.accept()
                CONNECTIONS.append(newSock)
                newUID = randint(10**constants.UID_LENGTH, 10**(constants.UID_LENGTH + 1) - 1)
                newClient = client(newUID, "Guest" + str(newUID), newAddr, None)
                CLIENTS.append(newClient)
                print ("Client (%s:%s) connected" % newAddr + " | Assigned uid=" + str(newUID))
            # some incoming message from a client
            else :
                # data recieved from client, process it
                data = sock.recv(constants.BUFFER_SIZE).decode()
                if data:
                    broadcast("\r" + '<' + CLIENTS[CONNECTIONS.index(sock)].name + '> ' + data)
except KeyboardInterrupt :
    print ("\nPressed Ctrl + c")
finally :
    server_socket.close()

print ("Goodbye.")
sys.exit()
