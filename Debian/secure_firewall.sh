#!/bin/sh

echo "Hardening Firewall"

ufw logging full >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default deny outgoing >/dev/null 2>&1
ufw allow out 123/udp >/dev/null 2>&1
ufw allow out dns >/dev/null 2>&1
ufw allow out http >/dev/null 2>&1
ufw allow out https >/dev/null 2>&1
ufw allow out ftp >/dev/null 2>&1
ufw allow out smtp >/dev/null 2>&1
ufw allow out smtps >/dev/null 2>&1
ufw allow out 'Mail submission' >/dev/null 2>&1
ufw allow out ssh >/dev/null 2>&1
#Allow new SSH PORT
ufw allow in "5922"/tcp >/dev/null 2>&1

#if [[ -n "$fwPort" ]]; then
#    IFS=',' read -ra ADDR <<<"$fwPort"
#    for i in "${ADDR[@]}"; do
#        ufw allow in "$i" >/dev/null 2>&1
#    done
#fi

echo "Configured Firewall successfully"
echo "Enabling Firewall"
ufw --force enable >/dev/null 2>&1
echo "Firewall enabled."
