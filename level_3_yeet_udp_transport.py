from argparse import ArgumentParser
from sys import argv

from scapy.compat import raw
from scapy.layers.inet import IP, UDP
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

    packet = IP(dst=args.ip)
    packet /= UDP(dport=55555, sport=55555)

    packet.add_payload(b"[x)0.0(x]")

    packet.show2()

    print(f"The raw packet:\n{raw(packet)}")

    send(packet)
