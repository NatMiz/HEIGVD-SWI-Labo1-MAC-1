# source: https://www.thepythoncode.com/article/create-fake-access-points-scapy

from scapy.all import *
import threading 

def fakeAP(ssid):
    print(ssid)
    # interface to use to send beacon frames, must be in monitor mode
    iface = "wlan0mon"
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
    sendp(frame, inter=0.1, iface=iface, loop=1)

print(len(sys.argv))

if len(sys.argv) == 1:
    f = open("fakeAP.txt", "r")
    line = f.readline()
    while line:
        threadAP = threading.Thread(target=fakeAP, args=(line,))
        threadAP.start()
        line = f.readline()
else:
    for x in range(0, int(sys.argv[1])):
        threadAP = threading.Thread(target=fakeAP, args=("Fake AP",))
        threadAP.start()
    

  

