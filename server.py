# Nate Stewart
# 02/27/16
# Network Encryption Server
 
import socket, select, sys
# Import constants file
import constants
# Grab a random number generator for the uid's and keys
from random import randint
# Used in packing the packets
import struct
# Import numpy for vectorized math
import numpy as np

# Class to store important information about the clients connected to the server
class client(object) :
    def __init__(self, uid, username, publicKey) :
        self.uid = uid
        self.username = username
        self.publicKey = publicKey

#Function to broadcast chat messages to all connected clients
def broadcast (sock, message) :
    #Do not send the message to master socket and the client who has send us the message
    for socket in CONNECTIONS :
        if socket != server_socket and socket != sock :
            try :
                socket.send(message)
            except :
                # broken socket connection may be, chat client pressed ctrl+c for example
                disconnect(socket)

# Encipher the message with the provided key.
# Return the enciphered message as a string of bytes
def encrypt(message, key) :
    # Split the message into an array of characters. Encrypt those characters using given key and modulo
    charArray = (np.array([ord(c) for c in message]) + key) % constants.COMMON_MODULO
    # Setup a byte format and pack the character array into a byte array
    byteFmt = ">%dI" % len(charArray)
    byteArray = struct.pack(byteFmt, *charArray)
    
    return byteArray

# Decipher the message with the symmetric key.
# Return the deciphered message as a string of characters
def decrypt(message) :
    global SYM_KEY
    # Setup the format needed to decipher the string of bytes
    byteFmt = ">%dI" % (len(message) // 4)
    # Grab an array of unencrypted characters from the unpacked byte array
    charArray = (np.array(struct.unpack(byteFmt, message)) - SYM_KEY) % constants.COMMON_MODULO
    # Convert characters into a string and return
    return ''.join([chr(i) for i in charArray])
    
# Server pack method.
# Key exchange : identity = uid, message = symmetric key
# Connect      : identity = username, message = none
# Disconnect   : identity = username, message = none
# Termination  : identity = none, message = none
# Message      : identity = username, message = message
# Set username : identity = none, message = "username_old -> username_new"
def pack(flag, identity, message) :
    global SYM_KEY
    packet = struct.pack(">B", flag)
    if flag == constants.FLAG_KEY_XCG :
        packet = packet + message # message has already been enciphered
    elif flag == constants.FLAG_CONNECT :
        packet = packet + encrypt(identity.rjust(constants.USERNAME_LENGTH_MAX), SYM_KEY)
    elif flag == constants.FLAG_DISCONNECT :
        packet = packet + encrypt(identity.rjust(constants.USERNAME_LENGTH_MAX), SYM_KEY)
    elif flag == constants.FLAG_SERVER_TERMINATION :
        packet = packet
    elif flag == constants.FLAG_MESSAGE :
        packet = packet + encrypt(identity.rjust(constants.USERNAME_LENGTH_MAX) + message, SYM_KEY)
    elif flag == constants.FLAG_SET_USERNAME :
        packet = packet + encrypt(message, SYM_KEY)
    else :
        raise ValueError('Cannot pack message. Invalid flag: ' + str(flag))
    return packet

# Server unpack method.
# Key exchange : user specific pub_key is stored
# Disconnect   : disconnect message output to stdout and broadcast to all clients
# Message      : message broadcast to all clients
# Set username : Set username of client specified by conn
def unpack(conn, packet) :
    #print repr(packet)
    flag, = struct.unpack(">B", packet[0:1])
    message = packet[1:len(packet)]
    currClient = CLIENTS[CONNECTIONS.index(conn)]
    if flag == constants.FLAG_KEY_XCG :
        pub_key, = struct.unpack(">I", message[0:len(message)])
        client.publicKey = pub_key
        message = currClient.uid + str(SYM_KEY)
        conn.send(pack(constants.FLAG_KEY_XCG, None, encrypt(message, pub_key)))
    elif flag == constants.FLAG_DISCONNECT :
        disconnect(conn)
    elif flag == constants.FLAG_MESSAGE :
        message = decrypt(message)
        broadcast(conn, pack(constants.FLAG_MESSAGE, currClient.username, message[constants.UID_LENGTH:len(message)]))
    elif flag == constants.FLAG_SET_USERNAME :
        message = decrypt(message)
        pusername = message[constants.UID_LENGTH:len(message)]
        oldusername = currClient.username
        if len(pusername) == 0 :
            currClient.username = "Guest%s" % currClient.uid
        else :
            currClient.username = pusername
        broadcast(conn, pack(constants.FLAG_SET_USERNAME, None, "%s -> %s" % (oldusername,pusername)))
    else :
        raise ValueError('Cannot unpack packet. Packet may have been corrupted. Invalid flag: ' + str(flag))

# Close connection 'conn' and remove from global structures
def disconnect(conn) :
    global CLIENTS
    global CONNECTIONS
    currClient = CLIENTS[CONNECTIONS.index(conn)]
    print 'Client %s ' % currClient.uid + " has disconnected from the chat"
    broadcast(conn, pack(constants.FLAG_DISCONNECT, currClient.username, None))
    conn.close()
    del CLIENTS[CONNECTIONS.index(conn)]
    CONNECTIONS.remove(conn)
    
# Prevent the server from being started from an embed
if __name__ != "__main__" :
    print ("Server cannot be embeded.")
    sys.exit(1)
    
if(len(sys.argv) < 2) :
    PORT = constants.DEFAULT_PORT
else :
    PORT = int(sys.argv[1])

# A list of the connections with the server
CONNECTIONS = []
# A list of the clients currently connected to the server, indexed to match the read_connections
CLIENTS = []
# The symmetric key generated every time the server opens up
SYM_KEY = randint(constants.KEY_SIZE_MIN, constants.KEY_SIZE_MAX)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((constants.HOST, PORT))
server_socket.listen(10)

# Add server socket to the list of readable connections
CONNECTIONS.append(server_socket)
CLIENTS.append(1) # server_socket is the exception.
# Let user know what host and port combination the socket is listening on
print "Listening on " + socket.gethostname() + " on port " + str(PORT)

# Wrap the  unterminated loop in interrupt detection to safely terminate all connections
try :
    while True:
        # Get the list sockets which are ready to be read through select
        read_sockets, write_sockets, error_sockets = select.select(CONNECTIONS,[],[])

        for sock in read_sockets:
            #New connection
            if sock == server_socket:
                # Handle the case in which there is a new connection recieved through server_socket
                newSock, newAddr = server_socket.accept()
                CONNECTIONS.append(newSock)
                newUID = str(randint(10**(constants.UID_LENGTH - 1), 10**constants.UID_LENGTH - 1)) 
                newUsername = "Guest%s" % newUID
                newClient = client(newUID, newUsername, None)
                CLIENTS.append(newClient)
                broadcast(newSock, pack(constants.FLAG_CONNECT, newUsername, None))
                print ("Client (%s:%s) connected" % newAddr + " | Assigned uid: %s" % newUID)

            #Some incoming message from a client
            else:
                # Data recieved from client, process it
                try:
                    currClient = CLIENTS[CONNECTIONS.index(sock)]
                    #In Windows, sometimes when a TCP program closes abruptly,
                    # a "Connection reset by peer" exception will be thrown
                    data = sock.recv(constants.BUFFER_SIZE)
                    if data:
                        unpack(sock, data)   

                except:
                    disconnect(sock)
                    continue

except KeyboardInterrupt :
    print '\nPressed Ctrl + c'
finally :
    broadcast(None, pack(constants.FLAG_SERVER_TERMINATION, None, None))
    server_socket.close()

print 'Goodbye.'
sys.exit(0)

