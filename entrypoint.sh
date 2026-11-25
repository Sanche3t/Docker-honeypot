#!/bin/bash
mkdir -p /export/cowrie /export/web /export/pcaps
mkdir -p /home/cowrie/cowrie/var/log/cowrie
chown -R cowrie:cowrie /home/cowrie/cowrie/var

# 1. Start tcpdump in background
tcpdump -i eth0 -s 0 -n -G 600 -w /export/pcaps/cap_%Y%m%d_%H%M%S.pcap &

# 2. Start Cowrie
su - cowrie -c "cd /home/cowrie/cowrie && . cowrie-env/bin/activate && bin/cowrie start"

# Symlink Cowrie JSON log to export
touch /home/cowrie/cowrie/var/log/cowrie/cowrie.json
ln -sf /home/cowrie/cowrie/var/log/cowrie/cowrie.json /export/cowrie/cowrie.json

# 3. Start Flask Web Honeypot
gunicorn -w 2 -b 0.0.0.0:8080 --chdir /app web_app:app &

echo "[+] Honeypot container running (Cowrie :2222/:2223, Flask :8080, tcpdump active)..."

# Keep container alive indefinitely
tail -f /dev/null
