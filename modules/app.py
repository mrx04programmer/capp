import sys, argparse
from static import *


W = '\033[37m'
R = '\033[1;31m'  # red
G = '\033[1;32m'  # green
O = '\033[0;33m'  # orange
B = '\033[1;34m'  # blue
P = '\033[1;35m'  # purple
C = '\033[1;36m'  # cyan
GRs = '\033[1;37m'  # gray

err = f"{O}ERR{W}"
add = f"{B}ADD{W}"
info = f"{G}INFO{W}"



def banner():
    print(f"{O}")

def dopper(utl, host):
    if "n" in utl:
        icmp_trace(host)

def main():
    if len(sys.argv) == 1:
        print(f"{err} Usage: python3 {sys.argv[0]} <options> <host> <port>")
    else:
        utl = sys.argv[1]
        host = sys.argv[2]
        banner()
        dopper(utl, host)

if __name__ == "__main__":
    try:
        main()
        #icmp_trace(target_host)
    except KeyboardInterrupt:
        print('\n'+err+' Interrumpido por teclado')
        exit()
