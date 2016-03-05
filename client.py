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
import time
# import needed functions from os to create 'recv' directory
import os
# check the error number of invalid connection 
import errno
# Import constants file
import constants

# A simple prompt written/flushed into stdout
def prompt() :
    outputName = "<"
    if name is not None :
        outputName = outputName + name
    else :
        outputName = outputName + constants.DEFAULT_PROMPT
    outputName = outputName + ">"
    sys.stdout.write(outputName)
    sys.stdout.flush()

# Unpack the byte object retrieved from the socket. Analyze the flag and perform a different action depending on what it is
def unpack(packet) :
    flag = int.from_bytes(data[:1], byteorder='big')
    numBytes = len(packet)
    message = data[1:numBytes-1].decode()
    if flag == constants.FLAG_KEY_XCG :
        symKey = message 
    elif flag == constants.FLAG_UID :
        UID = message
    elif flag == constants.FLAG_DISCONNECT :
        sys.stdout.write("\r" + '<' + message + '> has disconnected from chat.')
    elif flag == constants.FLAG_CONNECT :
        sys.stdout.write("\r" + '<' + message + '> has connected to chat.')
    elif flag == constants.FLAG_MESSAGE :
        uid = message[1:UID_LENGTH]
        message = message[UID_LENGTH:numBytes-1]
        sys.stdout.write("\r" + '<' + uid + '> ' + message)
    else :
        raise ValueError('Cannot unpack packet. Packet may have been corrupted. Invalid flag: ' + str(flag))

# Pack the flag, uid, and message inside a packet. Return this byte object to the caller to be sent across the network
# If a symmetric key is available, encrypt the uid and message before joining them with the plaintext flag
def pack(flag, message) :
    if flag == constants.FLAG_KEY_XCG : # Send the server my public key
        packet = b''.join([flag.to_bytes(1, byteorder='big'),
                message.encode()])
    elif flag == constants.FLAG_DISCONNECT :
        packet = b''.join([flag.to_bytes(1, byteorder='big'),
                UID.encode()])
    elif flag == constants.FLAG_MESSAGE :
        packet = b''.join([flag.to_bytes(1, byteorder='big'),
                UID.encode(),
                message.encode()])
    else :
        raise ValueError('Cannot pack message. Invalid flag: ' + str(flag))
    return packet

# Common disconnect steps when disconnecting from the server
def disconnect() :
    conn.send(pack(constants.FLAG_DISCONNECT, None)) 
    READ_CONNECTIONS.remove(conn)
    conn.close();
    conn = None

# Steps to connect to the ip:port combination provided
def connect(ip, port) :
    # setup a socket and connect to the host and port provided by the user
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    # ensure the socket can be created
    try :
        s.connect((ip, port))
        return {"code":0, "conn":s}
    except socket_error as e :
        # if e.errno doesn't equal 'connection refused', reraise the error 
        if e.errno != errno.ECONNREFUSED :
            raise e
        print ("Unable to connect to " + ip + " at port " + str(port))
        return {'code':1, 'conn':None}

if __name__ != "__main__" :
    print ("Client cannot be embeded.")
    sys.exit(1)

# A list of the connections with the server
READ_CONNECTIONS = [sys.stdin]
conn = None
name = None
publicKey = '1234567890'
symKey = None
UID = None
quit = 0

# Wrap interrupt detection
try:
    # Loop until /quit command is received
    while quit == 0 :
        prompt()
        # Figure out what command was sent and act accordingly
        # get sockets which are ready to be read
        sck_read,sck_write,sck_err = select.select(READ_CONNECTIONS,[],[])
        for sock in sck_read :
            # message from server
            if (sock == conn) :
                data = sock.recv(constants.BUFFER_SIZE)
                if not data : # disconnected from server
                    if sock == conn :
                        print ("Disconnected from server.")
                        READ_CONNECTIONS.remove(conn)
                        conn.close();
                        conn = None
                else :
                    unpack(data)
            # User entered message
            else :
                message = sys.stdin.readline().strip()
                if (message.split()[0] == "/connect") :
                    if len(message.split()) != 2 :
                        print ("Usage: '/connect <ip/hostname>'")
                        print ("\tex: /connect 123.456.789.0")
                        continue
                    if conn is not None :
                        print ("Connection already established. Cannot connect to another server.")
                        continue

                    # Attempt to connect to the specified port
                    connection = connect(message.split()[1], constants.DEFAULT_PORT)
                    if (connection['code'] == 1) :
                        continue 
                    else : # connection has been established
                        conn = connection['conn']
                        READ_CONNECTIONS.append(conn)
                        
                elif (message == "/quit") :
                    if conn is not None :
                        disconnect()
                    quit = 1
                    break
                elif (message == "/help") :
                    print ("\n/connect <ip/hostname> : connect to a server running at the provided ip/hostname")
                    print ("/disconnect : disconnect from a server without exiting the NEC")
                    print ("/quit : quit the NEC")
                    print ("/setname <name> : Set your name to something other than the default.\n")
                elif (message == "/disconnect") :
                    if conn is not None :
                        disconnect()
                    else :
                        print ("You are not currently connected to a server.")
                elif (message.split()[0] == "/setname") :
                    if len(message.split()) == 2 :
                        tempName = message.split()[1]
                        if len(tempName) >= constants.USERNAME_LENGTH_MIN and len(tempName) <= constants.USERNAME_LENGTH_MAX :
                            name = tempName
                        else :
                            print ("Username must be between " + constants.USERNAME_LENGTH_MIN + " and " + constants.USERNAME_LENGTH_MAX + " characters long.")
                    else :
                        name = None
                else :
                    if conn is not None :
                        conn.send(pack(constants.FLAG_MESSAGE, message))
                    else:
                        print ("Use '/help' to see a list of commands.")
        
except KeyboardInterrupt:
    print ("\nPressed Ctrl + c")

print ("Goodbye.")
sys.exit()

