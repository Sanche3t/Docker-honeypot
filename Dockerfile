FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git python3-venv python3-pip build-essential libssl-dev libffi-dev \
    libpython3-dev tcpdump procps curl iptables \
    && rm -rf /var/lib/apt/lists/*

# Setup Cowrie User
RUN adduser --disabled-password --gecos "" cowrie
USER cowrie
WORKDIR /home/cowrie
RUN git clone https://github.com/cowrie/cowrie.git /home/cowrie/cowrie
WORKDIR /home/cowrie/cowrie
RUN python3 -m venv cowrie-env && \
    . cowrie-env/bin/activate && \
    pip install --upgrade pip && \
    pip install --upgrade -r requirements.txt

# Configure Cowrie directly with clean config
RUN mkdir -p etc && \
    printf "[honeypot]\nhostname = srv04-prod\n\n[ssh]\nenabled = true\nlisten_endpoints = tcp:2222:interface=0.0.0.0\n\n[telnet]\nenabled = true\nlisten_endpoints = tcp:2223:interface=0.0.0.0\n\n[output_jsonlog]\nenabled = true\nlogfile = var/log/cowrie/cowrie.json\n" > etc/cowrie.cfg

USER root
# Setup Flask Honeypot dependencies
RUN pip3 install flask gunicorn

# Setup App and Volumes
RUN mkdir -p /app /export/cowrie /export/web /export/pcaps

COPY entrypoint.sh /entrypoint.sh
RUN tr -d '\r' < /entrypoint.sh > /entrypoint_clean.sh && \
    mv /entrypoint_clean.sh /entrypoint.sh && \
    chmod +x /entrypoint.sh

EXPOSE 2222 2223 8080

ENTRYPOINT ["/entrypoint.sh"]
