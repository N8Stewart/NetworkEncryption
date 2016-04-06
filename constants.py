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
USERNAME_LENGTH_MIN = 3
USERNAME_LENGTH_MAX = 16
# Length of the UID (min:10^(UID_LENGTH) | max:10^(UID_LENGTH + 1) - 1)
UID_LENGTH = 8 
# The common modulo value for all public/private interactions
COMMON_MODULO = 256
# Max and min values for the private key
PRIVATE_KEY_MIN = 1
PRIVATE_KEY_MAX = 255
# Max and min values for the symmetric key
SYMMETRIC_KEY_MIN = 1
SYMMETRIC_KEY_MAX = 255

# **** Flags for message headers ****
FLAG_KEY_XCG = 1
FLAG_MESSAGE = 2
FLAG_CONNECT = 3
FLAG_DISCONNECT = 4
FLAG_SERVER_TERMINATION = 5
FLAG_SET_USERNAME = 6
