from socket import *
import struct
from binascii import unhexlify
from checksum3 import *


fd=open("info.txt","r")
Lines=fd.readlines()


dest_mac=Lines[6][:17]
src_mac=Lines[5][:17]
proto3="08 00"
ver="45"
diff="00"
t_len="00 28"
id="07 c3"
flags="40 00"
ttl="40"
proto4="06"
csum3="00 00"
src_ip = inet_aton(Lines[2]).hex()  # source IP address
dest_ip = inet_aton(Lines[0]).hex()  # destination IP address
src_port="%04x" %int(Lines[3])
dest_port="%04x" %int(Lines[1])

seq_num="17 49 30 d1"
ack="09 92 66 43"
h_len="50 02"
w_size="72 10"
csum4="00 00"
up="00 00"
interface0=Lines[4].strip()
##
reserved ="00"
tcp_header_l="00 14"#20b
ff="00 00"#Flags and Fragment Offset
##
dest_mac=dest_mac.replace(":","")
src_mac=src_mac.replace(":","")

#build tcp segment
def buildTcpSegment():
	global csum4
	#print(tcp_header_l)
	segment_tcp=[
		#pseudo header
		src_ip,
		dest_ip,
		reserved,
		proto4,
		tcp_header_l,
		#main header
		src_port,
		dest_port,
		seq_num,
		ack,
		tcp_header_l,
		w_size,
		csum4,
		up
	]
	sum_tcp=""
	for i in range(0,len(segment_tcp)):
		sum_tcp+=segment_tcp[i]
	sum_tcp=sum_tcp.replace(' ','')
	sum_tcp=' '.join(sum_tcp[i:i+2] 
				for i in range(0, len(sum_tcp),2))
	csum4=cs(sum_tcp)
	#print(csum4)
	#print(tcp_header_l)
	segment_tcp2=[
		#main header
		src_port,
		dest_port,
		seq_num,
		ack,
		tcp_header_l,
		w_size,
		csum4,
		up
	]
	message_tcp=""
	for x in range(0,len(segment_tcp2)):
	    message_tcp+=segment_tcp2[x]
	#print(message_tcp)
	message_tcp=message_tcp.replace(' ','')
	return message_tcp

#build ip packet
def buildIpPacket(message_tcp):
	global csum3
	ip_packet=[
		ver,
		diff,
		t_len,
		id,
		ff,
		ttl,
		proto4,
		csum3,
		src_ip,
		dest_ip,
		message_tcp
	]
	sum_ip=""
	for i in range(len(ip_packet)-1):
		sum_ip+=ip_packet[i]
	sum_ip=sum_ip.replace(' ','')
	sum_ip=' '.join(sum_ip[i:i+2] 
				for i in range(0, len(sum_ip),2))
	csum3=cs(sum_ip)
	#print(csum3)
	ip_packet2=[
		ver,
		diff,
		t_len,
		id,
		ff,
		ttl,
		proto4,
		csum3,
		src_ip,
		dest_ip,
		message_tcp
	]
	message_ip=""
	for x in range(len(ip_packet2)):
	    message_ip+=ip_packet2[x]
	#print(message_ip)
	message_ip=message_ip.replace(' ','')
	return message_ip

#build ethernet frame
def buildEthernetFrame(message_ip):
	ethernet_frame=[
		dest_mac,
		src_mac,
		proto3,
		message_ip
	]
	message_eth=""
	for x in range(len(ethernet_frame)):
	    message_eth+=ethernet_frame[x]
	#print(message_eth)
	return message_eth

#send message
def sendMessage(destport):
	global dest_port 
	dest_port=destport
	message_tcp=buildTcpSegment()
	message_ip=buildIpPacket(message_tcp)
	message_eth=buildEthernetFrame(message_ip)
	final_message=message_eth.replace(" ","")
	#print(final_message)
	pkt = unhexlify(final_message)
	s = socket(AF_PACKET, SOCK_RAW)
	s.bind((interface0, 0))
	#print("##########################")
	#print(pkt)
	s.send(pkt)
	
	print("sent TCP SYN packet to port "+str(int(destport,16)))


if __name__=='__main__':
	sendMessage(dest_port)
