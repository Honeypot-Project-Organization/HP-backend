#!/usr/bin/env bash
# Blocks the Cowrie container from opening ANY outbound connection, while
# still letting attackers connect in to it. Run once on the VPS, as root,
#
# Why this is needed: Docker routes container traffic through the FORWARD
# chain and inserts its own rules ahead of ufw, so `ufw default deny
# outgoing` never applies to containers. Docker's DOCKER-USER chain is the
# supported place for rules that containers can't bypass. We put the rule
# in /etc/ufw/after.rules so ufw re-applies it on every boot/reload.
set -euo pipefail

SUBNET="172.30.0.0/24"   # must match networks.honeynet in docker-compose.yml
RULES=/etc/ufw/after.rules
MARK_BEGIN="# BEGIN honeypot-egress-block"
MARK_END="# END honeypot-egress-block"

if [[ $EUID -ne 0 ]]; then echo "Run with sudo." >&2; exit 1; fi
command -v ufw >/dev/null || { echo "ufw is not installed." >&2; exit 1; }

cp "$RULES" "$RULES.bak.$(date +%Y%m%d%H%M%S)"
# Remove any previous copy of our block, then append a fresh one.
sed -i "/$MARK_BEGIN/,/$MARK_END/d" "$RULES"
cat >> "$RULES" <<RULES_EOF
$MARK_BEGIN
*filter
:DOCKER-USER - [0:0]
# Replies to connections attackers opened TO the honeypot are allowed;
# any NEW connection FROM the honeypot's network is dropped and logged.
-A DOCKER-USER -s $SUBNET -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A DOCKER-USER -s $SUBNET -m conntrack --ctstate NEW -m limit --limit 6/min -j LOG --log-prefix "[HONEYPOT-EGRESS-BLOCK] "
-A DOCKER-USER -s $SUBNET -j DROP
-A DOCKER-USER -j RETURN
COMMIT
$MARK_END
RULES_EOF

# Also stop the honeypot container from reaching services on the VPS
# itself (e.g. your real SSH on port 2200) via the Docker gateway address.
# That traffic goes through INPUT, which ufw does control.
if ! ufw status | grep -q "$SUBNET"; then
    ufw insert 1 deny in from "$SUBNET" comment "honeypot container -> host"
fi

ufw reload
# ufw reload doesn't always touch DOCKER-USER if Docker created it first;
# restarting Docker makes sure the chain is in its final order.
systemctl restart docker

echo
echo "Installed. Current DOCKER-USER chain:"
iptables -S DOCKER-USER
echo
echo "Verify (should FAIL/time out):"
echo "  docker run --rm --network honeypot_honeynet python:3.12-slim \\"
echo "    python -c \"import urllib.request; urllib.request.urlopen('https://example.com', timeout=5)\""
echo "Verify the shipper still works:  docker compose logs --tail 20 log-shipper"
