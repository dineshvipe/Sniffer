import socket
import sys
from struct import *

def sniffer():
	try:
		s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
	except(socket.error,msg):
		print("socket could not be created. Error code: {} and message: {} ".format((msg[0]),(msg[1])))
		sys.exit()

	while True:
		packet=s.recvfrom(65565)
		packet=packet[0]
		ip_header=packet[:20]
		iph=unpack('!BBHHHBBH4s4s',ip_header)
		version_ihl=iph[0]
		version=version_ihl >> 4
		ihl=version_ihl & 0xF
		iph_length=ihl*4
		ttl=iph[5]
		protocol=iph[6]
		s_addr=socket.inet_ntoa(iph[8]);
		d_addr=socket.inet_ntoa(iph[9]);
		print("Version: {} IP Header Length: {} TTL: {} Protocol: {} \nSource Address: {} Dest. Address: {}".format(version,ihl,ttl,protocol,s_addr,d_addr))
		tcp_header=packet[iph_length:iph_length+20]
		tcph=unpack('!HHLLBBHHH',tcp_header)
		source_port=tcph[0]
		dest_port=tcph[1]
		sequence=tcph[2]
		acknowledgement=tcph[3]
		doff_reserved=tcph[4]
		tcph_length=doff_reserved >> 4
		print("Source Port: {} Dest Port: {} Sequence: {} Acknowledge: {} TCP Header Length: {}".format(source_port,dest_port,sequence,acknowledgement,tcph_length))
		h_size=iph_length+tcph_length*4
		data_size=len(packet)-h_size
		data=packet[h_size:]
		print("Data: {}\n".format(data))    