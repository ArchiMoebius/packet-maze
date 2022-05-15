from argparse import ArgumentParser
from sys import argv

from scapy.compat import raw
from scapy.layers.inet import IP
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

    packet = IP(flags="evil", dst=args.ip)

    packet.add_payload(b"haxor")

    packet.show2()

    print(f"The raw packet:\n{raw(packet)}")

    send(packet)
