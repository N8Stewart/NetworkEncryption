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

def prompt() :
    outputName = "<"
    if name is not None :
        outputName = outputName + name
    else :
        outputName = outputName + constants.DEFAULT_SHELL
    outputName = outputName + ">"
    sys.stdout.write(outputName)
    sys.stdout.flush()

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

# Wrap interrupt detection
try:
    # Loop until /quit command is received
    while True :
        prompt()
        # Figure out what command was sent and act accordingly
        # get sockets which are ready to be read
        sck_read,sck_write,sck_err = select.select(READ_CONNECTIONS,[],[])
        for sock in sck_read :
            # message from server
            if (sock == conn) :
                data = sock.recv(constants.BUFFER_SIZE)
                if not data : # disconnected from server
                    print ("Disconnected from server.")
                    READ_CONNECTIONS.remove(sock)
                    sock.close();
                    conn = None
                else :
                    sys.stdout.write(data)
            # User entered message
            else :
                message = sys.stdin.readline()
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
                        break
                    else :
                        conn = connection['conn']
                        READ_CONNECTIONS.append(conn)
                        
                elif (message == "/quit") :
                    if conn is not None :
                        READ_CONNECTIONS.remove(conn)
                        conn.close();
                        conn = None
                    break
                elif (message == "/help") :
                    print()
                    print ("/connect <ip/hostname> : connect to a server running at the provided ip/hostname")
                    print ("/disconnect : disconnect from a server without exiting the NEC")
                    print ("/quit : quit the NEC")
                    print()
                elif (message == "/disconnect") :
                    if conn is not None :
                        READ_CONNECTIONS.remove(conn)
                        conn.close();
                        conn = None
                    else :
                        print ("You are not currently connected to a server.")
                elif (message.split()[0] == "/setname") :
                    if len(message.split()) == 2 :
                        name = message.split()[1]
                    else :
                        name = None
                else :
                    if conn is not None :
                        conn.send(message.encode())
                    else:
                        print ("Use '/help' to see a list of commands.")
        
except KeyboardInterrupt:
    print ("\nPressed Ctrl + c")

print ("Goodbye.")
sys.exit()

