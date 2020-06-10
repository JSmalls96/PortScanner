import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *
from datetime import datetime
from time import strftime
from scapy.layers.inet import ICMP, IP, TCP
 
# python scanner.py [target-ip: 127.0.0.1] [start port: 1] [end port: 100]

start_clock = datetime.now()
# SYN flag
SYNACK = 0x12
# RST flag
RSTACK = 0x14
target = startport = endport = ports = None


def setup():
	global target
	global startport
	global endport

	if len(sys.argv) != 4: 
    		print("[!] Usage: %s target-ip startport endport"%(sys.argv[0]))
    		sys.exit(0)

	target = str(sys.argv[1])
	startport = int(sys.argv[2])
	endport = int(sys.argv[3])
	
	# check if startport is greater than endport
	# if so increment endport to be greater than startport
	while startport >= endport:
		endport+=1

# SYN => SYN-ACK => ACK = established tcp connection

def portscan(port):
	print("Scanning Port: "+str(port))
	srcport = RandShort()
	SYN_ACK_PKT = sr1(IP(dst = target)/TCP(sport=srcport, dport=port, flags="S"),timeout=10,verbose=0)
	if SYN_ACK_PKT != None:
		if SYN_ACK_PKT.getlayer(TCP).flags == SYNACK:
			return True
		else:
			return False
	RST_PKT = IP(dst = target)/TCP(sport=srcport,dport=port,flags="R")
	send(RST_PKT)

# craft ping packet, send to target to validate state
def checkHost(ip):
	try:
		ping = sr1 (IP(dst=ip)/ICMP(),timeout=1,verbose=0)
		print("\n[*] Target is Up, Begin Scan...")
	except:
		print("\n[!] Couldn't resolve target, Exitting...")
		sys.exit(1)


setup()
checkHost(target)
print ("[*] Scanning "+target+" Started at "+ strftime("%H:%M:%S")+ "!\n")
ports = range(startport,endport+1)
for port in ports:
    open = portscan(port)
    if open: 
        print ("[**] Port "+ str(port) + ": Open\n")
    else:
        print ("[*] Port "+ str(port) + ": Closed\n")

stop_clock = datetime.now()
print ("\n[*] Scan Completed!")
print ("\n[*] Scan duration: "+ str(stop_clock - start_clock))
