from argparse import ArgumentParser
from sys import argv

from scapy.compat import raw
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument(
        "--iface",
        help="The Interface on which to yeet packets (eth0)",
        type=str,
        required=True,
    )

    parser.add_argument(
        "--mac",
        help="The destination mac address (00:11:22:33:44:55)",
        type=str,
        required=True,
    )

    parser.add_argument(
        "--ip",
        help="The Destination IP address provided by the instructor (192.168.1.1)",
        type=str,
        required=True,
    )

    args = parser.parse_args(argv[1:])

    packet = Ether(dst=bytes(args.mac, "utf8"))
    packet /= ARP(
        hwsrc=b"13:37:00:CA:FE:00",
        hwdst=bytes(args.mac, "utf8"),
        pdst=bytes(args.ip, "utf8"),
        op=0xFFFF,
    )

    packet.show2()

    print(f"The raw packet:\n{raw(packet)}")

    print(packet.route())

    srp(packet, iface=args.iface, timeout=0)
