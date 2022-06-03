#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Packet Maze - this script is the entry point and user space presentation layer for
    the packet_maze.c eBPF filters which are leveraged to create an interactive training
    tool for budding network programming enthousiast's.
"""

import socket

from ctypes import c_int64
from os import system
from sys import exit
from threading import Thread
from time import sleep, time

from scapy.compat import raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from bcc import BPF

from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table
from rich.style import Style


HK_TO_NAME = {}
HK_TO_TASK_ID = {}


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
                # print(addr, sock.recv(32))
            except Exception:
                pass
            finally:
                sock.close()


tcp_server_thread = Thread(target=tcp_level, daemon=True)
tcp_server_thread.start()

job_progress = Progress(
    "{task.description}",
    BarColumn(
        style=Style(italic=True, dim=True, color="black"),
        complete_style=Style(italic=True, dim=True, color="green"),
        bar_width=100,
    ),
    TextColumn("{task.fields[level]}"),
    expand=True,
)

progress_table = Table.grid(expand=True)
progress_table.add_row(
    Panel(
        job_progress,
        title="[b]Competitor Progress",
        border_style="green",
        padding=(1, 2),
        expand=True,
    ),
)


def render_player_table():
    global HK_TO_TASK_ID
    global HK_TO_NAME

    for key, leaf in bpf_sessions.items():

        player_task_id = HK_TO_TASK_ID.get(key.value, "false")
        name = HK_TO_NAME.get(key.value, "🐧")

        if player_task_id == "false":
            HK_TO_TASK_ID[key.value] = job_progress.add_task(
                f"[white]{name} (#{key.value})", total=5, level=f"Level {leaf.level}"
            )
        else:
            job = job_progress._tasks.get(player_task_id, False)

            if job and not job.finished:

                while int(job.fields["level"].split(" ")[-1]) < int(leaf.level):
                    job_progress.advance(job.id)
                    level = f"Level {leaf.level}"

                    if leaf.level > job.total:
                        level = "Done!"

                    job_progress.update(
                        job.id,
                        description=f"[white]{name} (#{key.value})",
                        level=level,
                    )

                    if leaf.level > job.total:
                        job.finished_time = True
                        break


# cleanup function
def cleanup():
    global HK_TO_TASK_ID
    current_time = int(time())

    for key, _ in bpf_sessions.items():
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
                    player_task_id = HK_TO_TASK_ID.get(key.value, False)

                    if player_task_id:
                        job_progress.remove_task(player_task_id)
                        del HK_TO_TASK_ID[key.value]
        except:
            print("cleanup exception.")
    return


bpf_sessions = b.get_table("sessions")

system("reset")

try:
    with Live(progress_table, refresh_per_second=10):
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
                pass

            render_player_table()
            cleanup()

            sleep(0)

except KeyboardInterrupt:
    pass

sock.close()
b.remove_xdp(interface, 0)
cleanup()

try:
    tcp_server_thread.join(timeout=3)
except RuntimeError:
    pass

exit(0)
