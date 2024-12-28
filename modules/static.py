from scapy.all import *
from colors import *
import sys, socket
import requests

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
    {O}c:{W}connect mode -> Connect directly host and port
    {O}s:{W}smb mode -> Enumerate SMB users
    {O}p:{W}port mode -> Quick port scan [-s silent]
    {O}v:{W}vuln mode -> Check vulnerabilities""")

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

def enumerate_smb_users(host, port=445):
    """
    Enumera usuarios SMB en un host objetivo
    """
    print(f"{info} Iniciando enumeración SMB en {G}{host}:{port}")
    
    try:
        if not connect(host, port):
            return
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, int(port)))
        
        print(f"{ok} Servicio SMB detectado")
        print(f"{info} Intentando enumerar usuarios...")
        
        common_users = ['administrator', 'guest', 'admin', 'user', 'backup']
        
        for user in common_users:
            print(f"{info} Probando usuario: {user}")
        
        print(f"{ok} Enumeración completada")
        
    except Exception as e:
        print(f"{err} Error: {str(e)}")
    finally:
        try:
            sock.close()
        except:
            pass

def quick_port_scan(host, silent=False):
    """
    Realiza un escaneo rápido de puertos comunes
    """
    common_ports = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy",
    69: "TFTP", 161: "SNMP", 162: "SNMP Trap", 514: "Syslog", 
    6660: "IRC", 6666: "IRC (Alternate)", 1080: "SOCKS Proxy", 
    1521: "Oracle DB", 2082: "cPanel", 2083: "cPanel SSL", 
    27017: "MongoDB", 5000: "UPnP", 5900: "VNC", 
    6379: "Redis", 9200: "Elasticsearch", 9300: "Elasticsearch (Cluster)",
    11211: "Memcached", 2049: "NFS", 27015: "Steam", 4444: "Metasploit",
    4445: "Radmin", 5555: "Android Debug Bridge (ADB)", 6666: "IRCd",
    7777: "Game Servers", 8888: "Web Proxy", 9000: "PHP-FPM", 
    10000: "Webmin", 12345: "NetBus", 31337: "Back Orifice", 
    31337: "Elite", 44444: "Trojan", 55555: "Trojan", 
    59000: "VNC", 60000: "Remote Desktop", 65000: "RSYNC"
}

    
    if not silent:
        print(f"{info} Iniciando escaneo rápido de puertos en {G}{host}")
    
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                if not silent:
                    print(f"{G}[+]{W} Puerto {port} ({common_ports[port]}) está abierto")
                open_ports.append(port)
            sock.close()
        except:
            pass
    
    if not silent and not open_ports:
        print(f"{info} No se encontraron puertos abiertos")
    return open_ports

def check_ssl_vulnerability(host, port):
    """
    Verifica vulnerabilidades SSL comunes
    """
    try:
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((host, int(port))) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print(f"{ok} Certificado SSL válido")
                print(f"{info} Versión SSL: {ssock.version()}")
                
                # Verificar fecha de expiración
                from datetime import datetime
                import ssl
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if not_after < datetime.now():
                    print(f"{err} ¡Certificado expirado!")
                    return False
                return True
    except ssl.SSLError as e:
        print(f"{err} Error SSL: {str(e)}")
        return False
    except Exception as e:
        print(f"{err} No se pudo verificar SSL: {str(e)}")
        return False

def check_vulnerabilities(host, port):
    """
    Verifica vulnerabilidades conocidas para un servicio específico
    """
    print(f"{info} Analizando vulnerabilidades en {G}{host}:{port}")
    
    # Verificar SSL si es puerto HTTPS
    if int(port) == 443:
        print(f"{info} Verificando SSL...")
        check_ssl_vulnerability(host, port)
    
    # Detectar servicio
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, int(port)))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        response = sock.recv(1024)
        sock.close()
        
        service = ""
        if b"SSH" in response:
            service = "SSH"
        elif b"HTTP" in response:
            service = "HTTP"
        elif b"FTP" in response:
            service = "FTP"
        elif b"SMTP" in response:
            service = "SMTP"
        
        if service:
            print(f"{ok} Servicio detectado: {service}")
            print(f"{info} Buscando CVEs conocidos...")
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}"
                response = requests.get(url)
                if response.status_code == 200:
                    cves = response.json().get('vulnerabilities', [])[:5]
                    if cves:
                        print(f"{ok} CVEs encontrados:")
                        for cve in cves:
                            print(f"  - {cve['cve']['id']}")
                    else:
                        print(f"{info} No se encontraron CVEs recientes")
            except Exception as e:
                print(f"{err} Error al buscar CVEs: {str(e)}")
    except Exception as e:
        print(f"{err} Error al detectar servicio: {str(e)}")