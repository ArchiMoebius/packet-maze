from argparse import ArgumentParser
from ipaddress import IPv4Address
from sys import argv

from scapy.compat import raw
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send

if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument(
        "-i",
        "--ip",
        help="The Destination IP address provided by the instructor",
        type=str,
        required=True,
    )

    args = parser.parse_args(argv[1:])

    packet = IP(dst=args.ip) / ICMP(
        type=13,
        id=0x42,
        seq=88,
        ts_ori=int(IPv4Address("1.3.3.7")),
        ts_rx=0,
        ts_tx=0,
    )

    packet.show2()

    print(f"The raw packet:\n{raw(packet)}")

    send(packet)
