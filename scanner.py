


import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #to log Errors
import sys
import time
import socket

from scapy.all import *

if len(sys.argv) != 2: 
    print("Usage: %s target_host"%(sys.argv[0]))
    sys.exit(0)

target = str(sys.argv[1])
start_port = 1
end_port = 800

t = time.localtime()
current_time = time.strftime("%Y-%m-%d %H:%M IST", t)
ip = socket.gethostbyname(target)

print("Starting Nmap 7.80 (https://nmap.org) at "+current_time)
print("Nmap scan report for " + str(target) + " " + ip )
print("Host is up")

'''
 Iterate through the ports to see if the ports are open or closed 
=> sr1() is a variant of sr() - send and receive packets. sr1() returns only one packet
'''

closed_ports = 0
print("\nPORT\tSTATE")
for port in range(start_port, end_port):
    packet = IP(dst=target)/TCP(dport=port,flags = 'S') #sending a SYN flag to the target to establish TCP connection
    response = sr1(packet, timeout = 0.5, verbose = 0)
    if(response == None):
        print("%-7s Filtered"%(str(port)))

    else:
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12: #0x12 - [SYN,ACK]
                print("%-7s Open"%(str(port)))
                sr(IP(dst=target)/TCP(dport=response.sport, flags='R'), timeout = 0.5, verbose = 0) # R - [RST] send the reset packet to break the connection and move onto scanning the next port 
            elif response.getlayer(TCP).flags == 0x14: #[ACK,RST]
                closed_ports += 1
        elif(response.haslayer(ICMP)):
            if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                print("%-7s Filtered"%(str(port)))

print("Not shown: "+ str(closed_ports) +" closed ports")



