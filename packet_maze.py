import socket
import time

from ctypes import c_int64, c_ubyte
from sys import stdout, exit
from threading import Thread

from scapy.compat import raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from bcc import BPF  # 1
from bcc.utils import printb

MAX_AGE_SECONDS = 5

HK_TO_NAME = {}


def get_eth_key(eth):

    hk = 9001

    def calculate(s, v):
        c = 0
        for i in range(0, len(s), 2):
            v ^= int(int.from_bytes(bytes.fromhex(s[i] + s[i + 1]), "big") * c)
            c += 1

        return v

    return calculate(eth.dst.replace(":", ""), calculate(eth.src.replace(":", ""), hk))


interface = "enp9s0"

b = BPF(src_file="packet_maze.c")

b.remove_xdp(interface, 0)

# XDP 'filter'
fn = b.load_func("packet_maze_xdp", BPF.XDP)
b.attach_xdp(interface, fn, 0)

# socket filter
bpf_func_filter = b.load_func("packet_maze_socket_filter", BPF.SOCKET_FILTER)

# create raw socket, bind it to interface
# attach bpf program to socket created
BPF.attach_raw_socket(bpf_func_filter, interface)

# get file descriptor of the socket previously
# created inside BPF.attach_raw_socket
socket_fd = bpf_func_filter.sock

ETH_P_ALL = 3
ETH_FRAME_LEN = 1514  # Max. octets in frame sans FCS
sock = socket.fromfd(socket_fd, socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)

# set it as blocking socket
sock.setblocking(True)
sock.settimeout(1)


def tcp_level():
    with socket.create_server(
        ("0.0.0.0", 55555),
        family=socket.AF_INET,
        reuse_port=True,
    ) as tcpserver:
        while True:
            try:
                sock, addr = tcpserver.accept()
                print(addr, sock.recv(32))
            except Exception:
                pass
            finally:
                sock.close()


tcp_server_thread = Thread(target=tcp_level, daemon=True)
tcp_server_thread.start()

# cleanup function
def cleanup():
    current_time = int(time.time())

    for key, leaf in bpf_sessions.items():
        try:
            current_leaf = bpf_sessions[key]
            # set timestamp if timestamp == 0
            if current_leaf.timestamp == 0:
                current_leaf.timestamp = current_time
                bpf_sessions[key] = current_leaf
            else:
                # delete older entries
                if current_time - current_leaf.timestamp > current_leaf.lifespan:
                    del bpf_sessions[key]
        except:
            print("cleanup exception.")
    return


bpf_sessions = b.get_table("sessions")

try:
    while True:

        try:
            packet = Ether(sock.recv(ETH_FRAME_LEN))

            hk = get_eth_key(packet[Ether])

            player = bpf_sessions.get(c_int64(hk), False)

            if player:

                if IP in packet and packet.payload and player.level == 2:
                    # player.name = (c_ubyte * 11).from_buffer_copy(
                    #    raw(packet[IP].payload[0:10]) + b"\x00"
                    # )

                    HK_TO_NAME[hk] = bytes(
                        raw(packet[IP].payload[0:10]) + b"\x00"
                    ).decode("utf8")

        except socket.timeout:
            stdout.write(".")
            pass

        for key, leaf in bpf_sessions.items():
            print(
                "Player: ",
                key.value,
                leaf.level,
                leaf.lifespan,
                HK_TO_NAME.get(key.value, "Nooby"),
            )

        cleanup()

except KeyboardInterrupt:  # 7
    pass

sock.close()
b.remove_xdp(interface, 0)  # 11
cleanup()

try:
    tcp_server_thread.join(timeout=3)
except RuntimeError:
    pass

exit(0)
