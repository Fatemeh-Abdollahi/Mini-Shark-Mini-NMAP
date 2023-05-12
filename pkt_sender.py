from socket import *
from binascii import unhexlify

message =input("What is your packet content? ")
pkt = unhexlify(message)

s = socket(AF_PACKET, SOCK_RAW)
interface= input("Which interface do you want to use? ")
s.bind((interface, 0))
print("Sent "+str(s.send(pkt))+"-byte packet on "+interface)

