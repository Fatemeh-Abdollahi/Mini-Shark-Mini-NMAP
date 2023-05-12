from tcp_syn_sender import *
import struct
from socket import *

ip_address=input("what is the target IP address?")
port_range=input("which ports do you want to scan?")

dest_ip = inet_aton(ip_address).hex()

port_range_arr=port_range.split("-")

start=int(port_range_arr[0])
end=int(port_range_arr[1])

for i in range(end-start):
	dest_port="%04x" %int(i+start)
	#print(dest_port)
	sendMessage(dest_port)
	print(dest_ip)
	
