from scapy.all import *
from colors import *
import sys, socket

err = f"{O}ERR{W}"
add = f"{B}ADD{W}"
info = f"{G}INFO{W}"
ok = f"{G}OK{W}"
use = f"{err} Usage: python3 {sys.argv[0]} <options> <host> <port>"

def helper():
    print(f"""{B}Usage {W}python3 {sys.argv[0]} <options> <host> <port>
    {R}Options:
        {O}t:{W}normal mode -> Trace ICMP
        {O}h:{W}http mode -> HTTP Sniffer <Filter IP>
        {O}c:{W}connect mode -> Connect directly host and port""")

def connect(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"{info} connecting with {G}{host}:{port}")
        sock.connect((host, int(port)))
        print(f"{info} connected successful !")
        return True
    except ConnectionRefusedError:
        print(f"{err} port {port} not available ")
    except Exception as e:
        print(f'{err} conection error -> {O}{e}\n')

def icmp_trace(target, max_hops=30, timeout=2):
    ttl = 1
    while True:
        packet = IP(dst=target, ttl=ttl) / ICMP()

        reply = sr1(packet, verbose=False, timeout=1)

        if reply is None:
            print(f"{O}jump {ttl}: {R}*")
        else:
            print(f"{O}jump {ttl}{W}: {reply.src}{ok}")

        ttl += 1

        if reply is not None and reply.src == target:
            break

        if ttl > max_hops:
            break