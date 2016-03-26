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
    def __init__(self, uid, publicKey) :
        self.uid = uid
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
# Key exchange : uid = uid, message = symmetric key
# Connect      : uid = uid, message = none
def pack(flag, uid, message) :
    packet = struct.pack(">I", flag)
    if flag == constants.FLAG_KEY_XCG :
        packet = packet + uid.encode() + message.encode()
    elif flag == constants.FLAG_CONNECT :
        packet = packet + uid.encode()
    elif flag == constants.FLAG_DISCONNECT :
        packet = packet + uid.encode()
    elif flag == constants.FLAG_SERVER_TERMINATION :
        packet = packet
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
    client = CLIENTS[CONNECTIONS.index(conn)]
    if flag == constants.FLAG_KEY_XCG :
        pub_key = message[0:len(message)]
        client.publicKey = pub_key
        conn.send(pack(constants.FLAG_KEY_XCG, client.uid, SYM_KEY))
    elif flag == constants.FLAG_DISCONNECT :
        puid = message[0:constants.UID_LENGTH]
        print 'Client %s ' % puid + "has disconnected from the chat"
        broadcast(conn, packet)
        disconnect(conn)
    elif flag == constants.FLAG_MESSAGE :
        broadcast(conn, packet)
    else :
        raise ValueError('Cannot unpack packet. Packet may have been corrupted. Invalid flag: ' + str(flag))

# Close connection 'conn' and remove from global structures
def disconnect(conn) :
    global CLIENTS
    global CONNECTIONS
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
                newClient = client(newUID, None)
                CLIENTS.append(newClient)
                broadcast(newSock, pack(constants.FLAG_CONNECT, newUID, None))
                print ("Client (%s:%s) connected" % newAddr + " | Assigned uid: %s" % newUID)

            #Some incoming message from a client
            else:
                # Data recieved from client, process it
                try:
                    clientUID = CLIENTS[CONNECTIONS.index(sock)].uid
                    #In Windows, sometimes when a TCP program closes abruptly,
                    # a "Connection reset by peer" exception will be thrown
                    data = sock.recv(constants.BUFFER_SIZE)
                    if data:
                        unpack(sock, data)   

                except:
                    broadcast(newSock, pack(constants.FLAG_DISCONNECT, clientUID, None))
                    print "Client <%s> has disconnected from the chat" % clientUID
                    disconnect(sock)
                    continue

    server_socket.close()
except KeyboardInterrupt :
    print '\nPressed Ctrl + c'
finally :
    broadcast(None, pack(constants.FLAG_SERVER_TERMINATION, None, None))
    server_socket.close()

print 'Goodbye.'
sys.exit(0)

