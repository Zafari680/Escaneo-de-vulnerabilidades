import nmap
import requests

def scan_ports(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sV')
    
    for host in scanner.all_hosts():
        print(f'Host: {host} ({scanner[host].hostname()})')
        print('Estado:', scanner[host].state())
        
        for proto in scanner[host].all_protocols():
            print(f'Protocolo: {proto}')
            ports = scanner[host][proto].keys()
            
            for port in ports:
                print(f'  Puerto: {port}, Estado: {scanner[host][proto][port]["state"]} - Servicio: {scanner[host][proto][port]["name"]}')

def check_web_vulnerabilities(url):
    common_vulnerabilities = {
        "SQL Injection": "' OR '1'='1" ,
        "XSS": "<script>alert('XSS')</script>",
    }
    
    for vuln, payload in common_vulnerabilities.items():
        test_url = f"{url}?test={payload}"
        response = requests.get(test_url)
        
        if payload in response.text:
            print(f"Posible {vuln} detectada en {test_url}")
        else:
            print(f"No se detectó {vuln} en {test_url}")

if __name__ == "__main__":
    target_host = input("Ingrese el objetivo (IP o dominio): ")
    scan_ports(target_host)
    
    target_url = input("https://www.facebook.com/")
    check_web_vulnerabilities(target_url)