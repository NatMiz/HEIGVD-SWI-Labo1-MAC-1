# SWI - Labo1-MAC1
# Date: 02.03.2020
# File: evil-twin-fake-channel.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# -*- coding: utf-8 -*-

# Evil twin and fake channel attack
from scapy.all import *

# SSID sniffer
# Based on the code of Adam Ziaja's ssid-sniffer.py (https://github.com/adamziaja/python/blob/master/ssid_sniffer.py)

ssid_list =  [] # List of the ssid in the proximity

def packetHandler(pkt):
    if pkt.haslayer(Dot11Beacon): # 802.11 beacon packets
        try:
            # We make sure to have neither duplicates, nor empty packets in the ssid list
            if(pkt.info not in ssid_list and len(pkt.info) > 0):
                ssid_list.append(pkt.info)
                # We print the list of retrieved ssids
                for i in range(len(ssid_list)):
                    print(str(i) + ' ' + str(ssid_list[i]))
        except AttributeError:
                print(AttributeError.values)
                pass

sniff(iface="wlan0mon", count=0, prn=packetHandler, store=0)