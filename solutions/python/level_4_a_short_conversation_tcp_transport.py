from argparse import ArgumentParser
from random import randint
from sys import argv

from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, sr

if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument(
        "--ip",
        help="The Destination IP address provided by the instructor (192.168.1.1)",
        type=str,
        required=True,
    )

    args = parser.parse_args(argv[1:])
    sport = randint(1024, 65535)
    dport = 55555

    ip_packet = IP(dst=args.ip, flags="DF")
    tcp_syn_packet = TCP(dport=dport, sport=sport, flags="S")

    packet = ip_packet
    packet /= tcp_syn_packet
    packet.show2()
    print(f"The raw SYN packet:\n{raw(packet)}")

    tcp_synack_packet = sr1(packet, timeout=5)

    if tcp_synack_packet != None:
        tcp_synack_packet.show2()
        print(f"The raw SYN/ACK packet:\n{raw(tcp_synack_packet)}")

        tcp_ack_packet = TCP(
            sport=sport,
            dport=dport,
            flags="PA",
            seq=tcp_synack_packet.ack,
            ack=tcp_synack_packet.seq + 1,
        )

        tcp_ack_packet.add_payload(b"ACK\x00\x01\x02\x03")

        packet = ip_packet
        packet /= tcp_ack_packet
        packet.show2()
        print(f"The raw ACK packet:\n{raw(packet)}")

        sr(packet, timeout=5)
    else:
        print("Failed you did, do again you must")
