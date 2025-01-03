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




def banner():
    print(f"""{O}
┏┓      
┃ ┏┓┏┓┏┓
┗┛┗┻┣┛┣┛
    ┛ ┛ {R}by {W}mrx04programmer""")

def dopper(utl):
    if "t" in utl:
        host = sys.argv[2]
        icmp_trace(host)
    elif "h" in utl:
        helper()
    elif "c" in utl:
        host = sys.argv[2]
        port = sys.argv[3]
        if len(sys.argv) == 4:
            connect(host, port)
        return f"{err}missing set port\n{use}"
    elif "s" in utl:
        if len(sys.argv) < 3:
            return f"{err}Falta especificar el host objetivo\n{use}"
        host = sys.argv[2]
        port = 445  # Puerto por defecto para SMB
        if len(sys.argv) > 3:
            port = sys.argv[3]
        enumerate_smb_users(host, port)
    elif "p" in utl:
        if len(sys.argv) < 3:
            return f"{err}Falta especificar el host objetivo\n{use}"
        host = sys.argv[2]
        silent = "-s" in sys.argv
        quick_port_scan(host, silent)
    elif "v" in utl:
        if len(sys.argv) < 4:
            return f"{err}Uso: python {sys.argv[0]} v <host> <port>\n{use}"
        host = sys.argv[2]
        port = sys.argv[3]
        check_vulnerabilities(host, port)
    else:
        return use
def main():
    if len(sys.argv) == 1:
        print(f"{err} Usage: python3 {sys.argv[0]} <options> <host> <port>")
    else:
        banner()
        utl = sys.argv[1]
        dopper(utl)

if __name__ == "__main__":
    try:
        main()
        #icmp_trace(target_host)
    except KeyboardInterrupt:
        print('\n'+err+' Interrumpido por teclado')
        exit()
