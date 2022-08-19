#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Packet Maze - this script is the entry point and user space presentation layer for
    the packet_maze.c eBPF filters which are leveraged to create an interactive training
    tool for budding network programming enthousiast's.
"""

import socket

from argparse import ArgumentParser
from ctypes import c_int64
from pathlib import PosixPath
from os import system
from sys import exit, argv
from threading import Thread
from time import sleep, time

try:
    from bcc import BPF
except ImportError:
    print("bcc required!\nFind your OS and follow their installation guide:\nhttps://github.com/iovisor/bcc/blob/master/INSTALL.md", flush=True)
    exit(0)

from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table
from rich.style import Style

from scapy.compat import raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether


ETH_P_ALL = 3
ETH_FRAME_LEN = 1514  # Max. octets in frame sans FCS

HK_TO_NAME = {}
HK_TO_TASK_ID = {}


def calculate(s, v):
    c = 0
    for i in range(0, len(s), 2):
        v ^= int(int.from_bytes(bytes.fromhex(s[i] + s[i + 1]), "big") * c)
        c += 1

    return v


def get_eth_key(eth):
    return calculate(
        eth.dst.replace(":", ""),
        calculate(
            eth.src.replace(":", ""),
            9001,
        ),
    )


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


def render_player_table(bpf_sessions, job_progress):
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


def cleanup(bpf_sessions, job_progress):
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


def main():
    parser = ArgumentParser()

    parser.add_argument(
        "--iface",
        help="The Interface on which to yeet packets (eth0)",
        type=str,
        required=True,
    )

    args = parser.parse_args(argv[1:])

    pm_bpf_handle = BPF(src_file=str(PosixPath(__file__).parent.joinpath("packet_maze.c")))

    pm_bpf_handle.remove_xdp(args.iface, 0)

    # XDP 'filter'
    pm_xdp = pm_bpf_handle.load_func("packet_maze_xdp", BPF.XDP)
    pm_bpf_handle.attach_xdp(args.iface, pm_xdp, 0)

    # socket filter
    pm_sock_filter = pm_bpf_handle.load_func(
        "packet_maze_socket_filter", BPF.SOCKET_FILTER
    )

    BPF.attach_raw_socket(pm_sock_filter, args.iface)

    pm_filtered_raw_socket = socket.fromfd(
        pm_sock_filter.sock, socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP
    )

    # set it as blocking socket
    pm_filtered_raw_socket.setblocking(True)
    pm_filtered_raw_socket.settimeout(1)

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

    bpf_sessions = pm_bpf_handle.get_table("sessions")

    system("reset")

    try:
        with Live(progress_table, refresh_per_second=10):
            while True:

                try:
                    packet = Ether(pm_filtered_raw_socket.recv(ETH_FRAME_LEN))

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

                render_player_table(bpf_sessions, job_progress)
                cleanup(bpf_sessions, job_progress)

    except KeyboardInterrupt:
        pass

    pm_filtered_raw_socket.close()
    pm_bpf_handle.remove_xdp(args.iface, 0)
    cleanup(bpf_sessions, job_progress)

    try:
        tcp_server_thread.join(timeout=3)
    except RuntimeError:
        pass

    exit(0)

if __name__ == "__main__":
    main()
