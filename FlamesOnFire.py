from scapy.all import *
import socket
import sys
import nmap
import os
import xml.etree.ElementTree as ET

def fire_scanner_with_ports(ip, start_port, end_port, ip_range=[]):
    fire_scanner(ip)
    if ip_range:
        for i in range(1, 21):
            if i <= len(ip_range):
                print("\nScanning " + ip_range[i-1])
                port_scanner(ip_range[i-1], start_port, end_port)

    else:
        print("\nScanning " + ip)
        port_scanner(ip, start_port, end_port)

if __name__ == '__main__':
    ip = input("Enter the IP address or subnet you want to scan: ")
    start_port = int(input("Enter the start port: "))
    end_port = int(input("Enter the end port: "))
    ip_range = []
    if input("Do you want to scan an IP range? (y/n): ").lower() == 'y':
        while True:
            ip_address = input("Enter the IP address: ")
            if not ip_address:
                break
            ip_range.append(ip_address)
    
    fire_scanner_with_ports(ip, start_port, end_port, ip_range)
    
def fire_scanner(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    print("IP\t\t\tMAC Address\n------------------------------------------")
    for client in clients_list:
        print(client["ip"] + "\t\t" + client["mac"])

def port_scanner(ip, start_port, end_port):
    for port in range(start_port, end_port+1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Port {port}: Open")
            # Determine service and version information
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            print(f"\tService: {service}")
            try:
                banner = sock.recv(1024).decode().strip()
                print(f"\tVersion: {banner}")
            except:
                pass
            # Scan for vulnerabilities using Nmap
            nm = nmap.PortScanner()
            nm.scan(ip, f"{port}")
            vulns = nm[ip]['tcp'][port]['script'].items()
            vuln_list = []
            for k, v in vulns:
                vuln_list.append({k:v})
            # Write vulnerabilities to an XML file
            root = ET.Element("Vulnerabilities")
            port_elem = ET.SubElement(root, "Port", number=str(port), service=service)
            for vuln in vuln_list:
                vuln_elem = ET.SubElement(port_elem, "Vuln")
                for k, v in vuln.items():
                    name_elem = ET.SubElement(vuln_elem, "Name")
                    name_elem.text = k
                    output_elem = ET.SubElement(vuln_elem, "Output")
                    output_elem.text = v
            tree = ET.ElementTree(root)
            filename = f"vulns_{ip}_port_{port}.xml"
            tree.write(filename)
        else:
            print(f"Port {port}: Closed")
        sock.close()
