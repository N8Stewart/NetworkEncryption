#Tom Antenucci
#04/03/16
#Sniffs incoming packets to server.py port

import socket, sys
from struct import *

#create a socket to start monitoring packets
sniffinSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)


#Keep track of the number of packets processed for easy viewing
totalPckts = 1

while True:
	#look at the first packet in the buffer, specifically its ip header
	rawPckt = sniffinSocket.recvfrom(10000)
	pckt = rawPckt[0]
	iphPacked = pckt[0:20]

	#unpack the header using the unpack method provided in python and
	#the standard format for an ip header
	ipHead = unpack('!BBHHHBBH4s4s' , iphPacked)
	
	#this is complicated math used to determine the length of the
	#ip header
	version_ihl = ipHead[0]
	ihl = version_ihl & 0xF
	iphLen = ihl * 4
	
	#now that we've calculated the length of the ip header, retrieve
	#the packed tcp header
	tcphPacked = pckt[iphLen:iphLen+20]

	#unpack the tcp header using the unpack method and the standard
	#format for a tcp header 
	tcpHead = unpack('!HHLLBBHHH' , tcphPacked)

	sPort = tcpHead[0]
	dPort = tcpHead[1]

	#the data offset and reserved locations on the header bit shifted
	#to get the entire length of the tcpHeader
	offsetReserved = tcpHead[4]
	tcphLen = offsetReserved >> 4
	dPortCheck = 0

	#if the destination port for the packet is the server port, then
	#we want to print the packet out
	if dPort == 5989:
		print 'Current Packet: ' + str(totalPckts)
		print 'Source Port:' + str(sPort)
		print 'Destination Port:' + str(dPort)
		dPortCheck = 1
	
	#The total size of the combined header is calculated and subtracted
	#from the length of the total packet so only the data remains
	totalHeaderSize = iphLen + tcphLen * 4
	sizeOfData = len(pckt) - totalHeaderSize
	
	
	pcktData = pckt[totalHeaderSize:]

	#if the current packet was pritned out, then also print out 
	#the raw data that came with the packet
	if dPortCheck == 1:
		print 'Raw Data: ' + pcktData
		print
		print
	
	totalPckts = totalPckts + 1