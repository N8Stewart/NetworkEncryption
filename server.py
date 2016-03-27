# Nate Stewart
# 02/27/16
# Network Encryption Server
 
import socket, select, sys
# Import constants file
import constants
# Grab a random number generator for the uid's
from random import randint
# Used in packing the packets
import struct

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
                             
# Server pack method.
# Key exchange : identity = uid, message = symmetric key
# Connect      : identity = username, message = none
# Disconnect   : identity = username, message = none
# Termination  : identity = none, message = none
# Message      : identity = username, message = message
def pack(flag, identity, message) :
    packet = struct.pack(">I", flag)
    if flag == constants.FLAG_KEY_XCG :
        packet = packet + identity.encode() + message.encode()
    elif flag == constants.FLAG_CONNECT :
        packet = packet + identity.rjust(constants.USERNAME_LENGTH_MAX).encode()
    elif flag == constants.FLAG_DISCONNECT :
        packet = packet + identity.rjust(constants.USERNAME_LENGTH_MAX).encode()
    elif flag == constants.FLAG_SERVER_TERMINATION :
        packet = packet
    elif flag == constants.FLAG_MESSAGE :
        packet = packet + identity.rjust(constants.USERNAME_LENGTH_MAX).encode() + message.encode()
    else :
        raise ValueError('Cannot pack message. Invalid flag: ' + str(flag))
    return packet

# Server unpack method.
# Key exchange : user specific pub_key is stored
# Disconnect   : disconnect message output to stdout and broadcast to all clients
# Message      : message broadcast to all clients
def unpack(conn, packet) :
    flag, = struct.unpack(">I", packet[0:4])
    message = packet[4:len(packet)]
    currClient = CLIENTS[CONNECTIONS.index(conn)]
    if flag == constants.FLAG_KEY_XCG :
        pub_key = message[0:len(message)]
        client.publicKey = pub_key
        conn.send(pack(constants.FLAG_KEY_XCG, currClient.uid, SYM_KEY))
    elif flag == constants.FLAG_DISCONNECT :
        disconnect(conn)
    elif flag == constants.FLAG_MESSAGE :
        broadcast(conn, pack(constants.FLAG_MESSAGE, currClient.username, message[constants.UID_LENGTH:len(message)]))
    elif flag == constants.FLAG_SET_USERNAME :
        pusername = message[constants.UID_LENGTH:len(message)]
        if len(pusername) == 0 :
            currClient.username = "Guest%s" % currClient.uid
        else :
            currClient.username = pusername
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
SYM_KEY = "1234567890"

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

