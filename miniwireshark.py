from socket import *
from struct import *
from binascii import unhexlify
#import re 


def ether(data):
	dest_mac, src_mac,proto = unpack('!6s 6s 2s',data[:14])
	#dest_mac = ':'.join(re.findall('..', dest_mac.hex()))
	#src_mac = ':'.join(re.findall('..', src_mac.hex()))
	return[dest_mac,src_mac,proto.hex(),data[14:]]
def ip(data):
	maindata = data
	data=unpack('! B s H 2s 2s B B 2s 4s 4s', data[:20])
	return [data[0]>>4, #version 
	(data[0]&(0x0F))*4, #header length 
	data[1].hex(), #Diffserv 
	data[2], #total_length 
	data[3].hex(), #ID 
	data[4].hex(), #flags 
	data[5], #ttl 
	data[6], #protocol 
	data[7].hex(), #check sum 
	inet_ntoa(data[8]), #source ip
	inet_ntoa(data[9]), #destination ip 
	maindata[(data[0]&(0x0F))*4:] #ip payload
	]
	
def TCP(data):
	mydata=unpack('! H H I I H H 2s 2s',data[:20])
	#flags = mydata[4]
	#ack = (flags & 16) >> 4
	#syn=(flags & 2) >> 1
	return[
	mydata[0],
	mydata[1],
	mydata[2],
	mydata[3],
	mydata[4],
	mydata[5],
	mydata[6],
	mydata[7]
	]
	
	
conn = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
print("wireshark started...")
while True:
	raw_dat, add = conn.recvfrom(65535)
	ether_shark=ether(raw_dat)
	if(ether_shark[2]=="0800"):
		ip_shark=ip(ether_shark[3])
		#print(type(ip_shark[7]),ip_shark[7])
		if(ip_shark[7]==6):
			tcp_shark=TCP(ip_shark[-1])
			#print(tcp_shark[4])
			if(tcp_shark[4] & 0x0012==0x0012):
				print("port "+str(tcp_shark[1])+" is open on "+str(ip_shark[-2]))


