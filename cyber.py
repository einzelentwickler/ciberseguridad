import nmap

def scan_network(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, '1-1024')  # Escanea los puertos del 1 al 1024
    
    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            print(f"Host: {host}")
            for proto in scanner[host].all_protocols():
                print(f"Protocolo: {proto}")
                ports = scanner[host][proto].keys()
                for port in ports:
                    print(f"Puerto: {port}\tEstado: {scanner[host][proto][port]['state']}")

target = input("Ingrese la dirección IP o el rango de la red a escanear: ")
scan_network(target)
