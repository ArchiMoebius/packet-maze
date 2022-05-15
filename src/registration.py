from scapy.compat import raw
from scapy.layers.l2 import ARP
from scapy.sendrecv import send

packet = ARP(
    hwsrc=b"ED:BE:13:37:55:00",
)

packet.add_payload("MyUserName")

packet.show2()

print(f"The raw packet:\n{raw(packet)}")

send(packet)
