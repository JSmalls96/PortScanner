# PortScanner
## Port Scanner built with python library scapy:

To run:
.\PortScanner> python scanner.py [TARGET IP] [START PORT] [END PORT]

Stealth TCP port probe.

Implementation using **three-way TCP handshake**.  
Send SYN probe --> if SYN/ACK is received then --> RST connection.  
Port determined to be open without completion of handshake.  
