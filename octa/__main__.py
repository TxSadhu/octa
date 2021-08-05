#! /usr/bin/env python3

import os
import random
import click
import socket
from .tcp_service import ports
from .top_ports import top_1000_ports
from scapy.all import ICMP, IP, sr1, TCP


# Define end host and TCP port range
# host = "45.33.32.156"
class bcolors:
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def version():
    return """⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⠀⣀⣀⣀⣀⣀⣀⠀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣰⡎⠀⣿⣿⣿⣦⡀⢀⣴⣿⡿⢱⣿⣿⡇⣿⣿⡎⢻⣿⣿⠀⣿⣿⣿⢹⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⡄⠀⠛⢿⣿⣿⣷⣸⣿⣿⡇⠈⠛⠿⠃⠛⢻⣵⣿⡟⠛⠀⢛⣛⣁⣸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀
⠘⣿⣿⣶⣤⣾⣿⣿⡏⢸⣿⣿⡇⢠⣶⣾⡆⠀⢸⣿⣿⡇⠀⢰⣿⣿⡟⠀⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠘⠻⢿⣿⣿⠿⠋⠀⠀⠙⠿⣿⣜⠿⣿⡇⠀⢸⣿⣿⡇⠀⠘⠿⣿⣷⣄⣽⣿⣿⠀ beta⠀

--------------------------------------⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """


def portservice(p):
    if p in ports:
        return ports.get(p)


# Send SYN with random Src Port for each Dst port
def portscan(host, dst_port):
    src_port = random.randint(1025, 65534)
    resp = sr1(
        IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags="S"),
        timeout=1,
        verbose=0,
    )
    try:
        if str(type(resp)) == "<type 'NoneType'>":
            print(
                f"{bcolors.WARNING}{dst_port}/filtered{bcolors.ENDC}"
                + " ["
                + portservice(str(dst_port))
                + "]"
            )

        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                # Send a gratuitous RST to close the connection
                send_rst = sr1(
                    IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags="R"),
                    timeout=1,
                    verbose=0,
                )
                print(
                    f"{bcolors.OKGREEN}{dst_port}/open{bcolors.ENDC}"
                    + " ["
                    + portservice(str(dst_port))
                    + "]"
                )

            elif resp.getlayer(TCP).flags == 0x14:
                pass

        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [
                1,
                2,
                3,
                9,
                10,
                13,
            ]:
                print(
                    f"{bcolors.WARNING}{dst_port}/filtered{bcolors.ENDC}"
                    + " ["
                    + portservice(str(dst_port))
                    + "]"
                )
    except:
        pass


@click.command()
@click.option("--ip", "-ip", prompt="Enter an IP address", help="Enter your IP address")
@click.option("--port", "-p", help="Enter your port to scan")
def scan(ip, port):
    click.echo(version())
    if os.geteuid() == 0:
        ip = socket.gethostbyname(ip)
        if not port:
            for prt in top_1000_ports:
                portscan(ip, int(prt))
        else:
            portscan(ip, int(port))
    else:
        print(
            f"{bcolors.WARNING}[ERROR] Scan stopped, please run as root{bcolors.ENDC}"
        )


if __name__ == "__main__":
    scan()
