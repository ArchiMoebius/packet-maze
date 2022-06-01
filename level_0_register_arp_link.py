from scapy.compat import raw
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

packet = Ether()
packet /= ARP(
    hwsrc=b"13:37:00:CA:FE:00",
    hwdst=b"00:25:22:f7:e8:de",
    pdst=b"192.168.7.148",
    op=0xFFFF,
)

packet.show2()

print(f"The raw packet:\n{raw(packet)}")

print(packet.route())

srp(packet, iface="eno1", timeout=0)
