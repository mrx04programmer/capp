from scapy.all import *
from colors import *
import sys

def helper():
    print(f"""
          {B}Usage {W}python3 {sys.argv[0]} <options> <host> <port>
          {R}Options:
            {O}t:{W}normal mode -> Trace ICMP
            {O}h:{W}http mode -> HTTP Sniffer <Filter IP>
            {O}c:{W}connect mode -> Connect directly host and port""")

def icmp_trace(target, max_hops=30, timeout=2):
    ttl = 1
    while True:
        packet = IP(dst=target, ttl=ttl) / ICMP()

        reply = sr1(packet, verbose=False, timeout=1)

        if reply is None:
            print(f"{O}jump {ttl}: {R}*")
        else:
            print(f"{O}jump {ttl}{W}: {reply.src}{G} OK")

        ttl += 1

        if reply is not None and reply.src == target:
            break

        if ttl > max_hops:
            break