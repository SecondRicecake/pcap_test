import os
import re
import fcntl, socket, struct
import binascii




'''Get IP and HA '''

#https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python

ipv4 = re.search(re.compile(r'(?<=inet )(.*)(?=\/)', re.M), os.popen('ip addr show wlp1s0').read()).groups()[0]


#https://stackoverflow.com/questions/159137/getting-mac-address

def getHA(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


'''
Change HA && IP string to usable integers
'''
ip = ipv4.split(".")

lst_IP = []
for i in ip:
	lst_IP.append(int(i,10))

mac = getHA('wlp1s0')
m = mac.split(":")

lst_HA = []
for i in m:
	lst_HA.append(int(i,16))


'''
Use struct to pack ARP package
'''

ARP =[
	struct.pack('!6B',255,255,255,255,255,255), #Broadcast
	struct.pack('!6B', *lst_HA),
	#struct.pack('!6B',0,194,198,167,34,4), #SHA
	struct.pack('!H',0x0806), #ARP type

	struct.pack('!H',0x0001),
	struct.pack('!H',0x0800),
	struct.pack('!B',0x06),
	struct.pack('!B',0x04),
	struct.pack('!H',0x0001),
	struct.pack('!6B', *lst_HA),
	struct.pack('!4B', *lst_IP),
	#struct.pack('!6B',0,194,198,167,34,4),
	#struct.pack('!4B',172,20,10,3), #SIP
	struct.pack('!6B',255,255,255,255,255,255),
	struct.pack('!4B',172,20,10,7) #victims IP

]


'''
Examples:

****************_ETHERNET_FRAME_****************
Dest MAC:         ffffffffffff
Source MAC:       00c2c6a72204
Type:             0806
************************************************
******************_ARP_HEADER_******************
Hardware type:    0001
Protocol type:    0800
Hardware size:    06
Protocol size:    04
Opcode:           0001
Source MAC:       00c2c6a72204
Source IP:        172.20.10.3
Dest MAC:         ffffffffffff
Dest IP:          172.20.10.7 #Who has 172.20.10.7?
*************************************************


HW type: 00 01 //2byte
P type: 08 00 //2byte
Hw size: 06 //1byte
P size: 04 //1byte
Opcode:00 01 //2byte
Sender MAC: 70 8b cd 30 2d d8 //6byte
Sender IP: c0 a8 01 01 //4byte
Target MAC: 00 00 00 00 00 00 //6byte
Target IP: c0 a8 01 e0 //4byte
'''

'''

Get Sender's Mac
'''

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) #htons: gets all packets
s.bind(("wlp1s0",0))#(device,0)
s.send(b''.join(ARP)) #join ARP list elms and send data to socket

packet = s.recvfrom(2048)
arp_reply = packet[0][20:22]
reply = binascii.hexlify(arp_reply)

#print type(reply)

if reply == '0002':
	reply_HA = packet[0][22:28]
	print "Source MAC:      ", binascii.hexlify(reply_HA)


s.close()

