# Nate Stewart
# 02/27/16
# Network Encryption Client

import socket, select, string, sys
# Import constants file
import constants
# Used in packing the packets
import struct

# Declare the global variables
UID = None
PUB_KEY = "8888888888"
SYM_KEY = None
USERNAME = None

# Client pack method. 
# Key exchange : uid = none, message = none
# Disconnect   : uid = uid, message = none
# Message      : uid = uid, message = message
def pack(flag, message) :
    global UID
    global PUB_KEY
    packet = struct.pack(">I", flag)
    if flag == constants.FLAG_KEY_XCG :
        packet = packet + PUB_KEY.encode()
    elif flag == constants.FLAG_DISCONNECT :
        packet = packet + UID.encode()
    elif flag == constants.FLAG_MESSAGE :
        packet = packet + UID.encode() + message.encode()
    elif flag == constants.FLAG_SET_USERNAME :
        packet = packet + UID.encode() + message.encode()
    else :
        raise ValueError('Cannot pack message. Invalid flag: ' + str(flag))
    return packet

#Client unpack method.
# Key exchange : global UID is set, global SYM_KEY is set
# Connect      : connection message output to stdout
# Disconnect   : disconnection message output to stdout
# Message      : message output to stdout
def unpack(conn, packet) :
    global UID
    global SYM_KEY
    flag, = struct.unpack(">I", packet[0:4])
    message = packet[4:len(packet)]
    if flag == constants.FLAG_KEY_XCG :
        UID = message[0:constants.UID_LENGTH]
        SYM_KEY = message[constants.UID_LENGTH:len(message)]
    elif flag == constants.FLAG_CONNECT :
        currUsername = message[0:constants.USERNAME_LENGTH_MAX].strip()
        message = "\r%s has connected to the chat.\n" % currUsername
        output(message)
    elif flag == constants.FLAG_DISCONNECT :
        currUsername = message[0:constants.USERNAME_LENGTH_MAX].strip()
        message = "\r%s has disconnected from the chat.\n" % currUsername
        output(message)
    elif flag == constants.FLAG_MESSAGE :
        currUsername = message[0:constants.USERNAME_LENGTH_MAX].strip()
        message = "\r%s: %s" % (currUsername,message[constants.USERNAME_LENGTH_MAX:len(message)])
        output(message)
    elif flag == constants.FLAG_SERVER_TERMINATION :
        conn.close()
        print '\nChat server has terminated.'
        sys.exit()
    elif flag == constants.FLAG_SET_USERNAME :
        output("\r%s\n" % message)
    else :
        raise ValueError('Cannot unpack packet. Packet may have been corrupted. Invalid flag: %s' % str(flag))

# Output message to the console and reprint the prompt
def output(message) :
    sys.stdout.write(message)
    prompt()
    
# Send the message to the socket and reprint the prompt
def send(socket, message) :
    try :
        socket.send(message)
    except :
        # broken socket connection. output disconnect message and exit
        socket.close()
        print '\nYou have been disconnected from the chat server.'
        sys.exit()

# Print the prompt and flush the stream
def prompt() :
    sys.stdout.write('<%s> ' % constants.DEFAULT_PROMPT)
    sys.stdout.flush()
 
# Connect to the provided host:port tuple
def connect(host, port) :
    # Initialize a socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(2)

    # connect to remote host
    try :
        server.connect((host, port))
    except :
        print 'Unable to connect to the chat server at %s:%s.' % (host,port)
        sys.exit()

    # Send the public key to the server
    send(server, pack(constants.FLAG_KEY_XCG, PUB_KEY))

    try :
        packet = server.recv(constants.BUFFER_SIZE)
    except :
        print 'Response from server timed out.'
        sys.exit()

    # Wait for the symmetric key from the server
    unpack(server, packet)
    if UID is not None :
        output('\rConnected to the chat server.\n')
    
    return server
    
def filterInput(server, message) :
    global USERNAME
    # If user is changing their name
    if message.split()[0] == "/setname" :
        if len(message.split()) == 2 :
            tempName = message.split()[1].strip()
            if len(tempName) >= constants.USERNAME_LENGTH_MIN and len(tempName) <= constants.USERNAME_LENGTH_MAX :
                USERNAME = tempName
                send(server, pack(constants.FLAG_SET_USERNAME, USERNAME))
            else :
                print "Username must be between %d and %d characters long." % (constants.USERNAME_LENGTH_MIN,constants.USERNAME_LENGTH_MAX)
        else :
            print "Setting username to default."
            USERNAME = None
            send(server, pack(constants.FLAG_SET_USERNAME, ""))
    else :
        send(server, pack(constants.FLAG_MESSAGE, message))
    prompt()
    
# Prevent the client from being started from an embed.
if __name__ != "__main__" :
    print ("Client cannot be embeded.")
    sys.exit(1)

# Grab host and port
if(len(sys.argv) < 2) :
    print 'Usage:\tpython client.py hostname [port]'
    sys.exit()
elif len(sys.argv) == 2 :
    port = constants.DEFAULT_PORT
else :
    port = int(sys.argv[2])
host = sys.argv[1]

server = connect(host, port)
socket_list = [sys.stdin, server]
    
# Wrap the  unterminated loop in interrupt detection to safely terminate all connections
try :
    while True:

        # Get the list sockets which are readable
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

        for sock in read_sockets:
            #incoming message from remote server
            if sock == server:
                data = sock.recv(constants.BUFFER_SIZE)
                if not data :
                    print 'Disconnected from chat server.\n'
                    sys.exit()
                # unpack the packet and print the message
                unpack(sock, data)
            #user entered a message
            else :
                filterInput(server, sys.stdin.readline())
except KeyboardInterrupt :
    sys.stdout.flush()
    print '\nPressed Ctrl + c'
finally :
    send(server, pack(constants.FLAG_DISCONNECT, None))
    server.close()

print 'Goodbye.'
sys.exit(0)
