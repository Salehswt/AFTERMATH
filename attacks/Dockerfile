# Attacker / telemetry-generator container.
# Holds the scenario runner + tooling to fire techniques at the victims and
# pull Suricata ET Open rules. ART atomics run on the victim; this box
# orchestrates and runs network-side actions (curl beacons, nmap, ssh).
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
      curl wget nmap netcat-openbsd sshpass python3 python3-yaml jq \
    && rm -rf /var/lib/apt/lists/*
COPY seed.sh /attacks/seed.sh
COPY runner.py /attacks/runner.py
COPY backdate.py /attacks/backdate.py
COPY validate_detections.py /attacks/validate_detections.py
RUN chmod +x /attacks/seed.sh
WORKDIR /attacks
CMD ["tail","-f","/dev/null"]
