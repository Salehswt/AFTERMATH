#!/usr/bin/env bash
# weaken.sh - misconfigure on purpose (weak prevention), keep auditd ON (rich
# detection). Runs at image build time.
set -e
u="${VICTIM_USER:-jdoe}"; p="${VICTIM_PASS:-Password123}"
useradd -m -s /bin/bash "$u" 2>/dev/null || true
echo "$u:$p" | chpasswd
usermod -aG sudo "$u"                       # weak: user is a sudoer
echo "$u ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/weak
# weak SSH: allow password auth + root login
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/'   /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
echo 'root:Toor1234' | chpasswd
# world-writable "share" + a weak cron (persistence surface)
mkdir -p /srv/share && chmod 777 /srv/share
echo '* * * * * root /usr/bin/curl -s http://172.30.0.99/beacon >/dev/null 2>&1' >/etc/cron.d/beacon || true
echo "[ OK ] linux victim weakened"
