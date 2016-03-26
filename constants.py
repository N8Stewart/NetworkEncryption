#!/usr/local/python-3.2.3/bin/python3.2

# Nate Stewart
# 02/27/16
# Network Encryption constants file

# Symbolic name meaning all available interfaces
HOST = '' 
# Port number that server will be listening on
DEFAULT_PORT = 5989
# Name of the shell when no connection is established
DEFAULT_PROMPT = "You"
# Constant buffer size to use when reading and writing to buffer
BUFFER_SIZE = 512
# Max and min size of the username
USERNAME_LENGTH_MIN = 4
USERNAME_LENGTH_MAX = 16
# Length of the UID (min:10^(UID_LENGTH) | max:10^(UID_LENGTH + 1) - 1)
UID_LENGTH = 8 

# **** Flags for message headers ****
FLAG_KEY_XCG = 1
FLAG_UID = 2
FLAG_MESSAGE = 3
FLAG_CONNECT = 4
FLAG_DISCONNECT = 5
FLAG_SERVER_TERMINATION = 6
