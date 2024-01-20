#!/bin/sh

echo "Securing SSH"

output=$(sed -n "/START_SSHD/,/END_SSHD/{ /START_SSHD/n; /END_SSHD/!p }" "./config.ini")
printf "%s" "$output" | tee /etc/ssh/sshd_config >/dev/null 2>&1
dos2unix /etc/ssh/sshd_config >/dev/null 2>&1

output=$(sed -n "/START_PAM_SSHD/,/END_PAM_SSHD/{ /START_PAM_SSHD/n; /END_PAM_SSHD/!p }" "./config.ini")
printf "%s" "$output" | tee -a /etc/pam.d/sshd >/dev/null 2>&1
dos2unix /etc/pam.d/sshd_config >/dev/null 2>&1

systemctl restart sshd.service >/dev/null 2>&1

echo "SSH secured successfully"
