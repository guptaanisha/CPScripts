#!/bin/bash

# Function to update and upgrade the system
system_update() {
    echo "Updating system..."
    apt-get update && apt-get -y upgrade
}

# Function to install necessary packages from deb_installPackages.sh
install_packages() {
    echo "Installing necessary packages..."
    apt-get install -y \
        ufw fail2ban apparmor apparmor-utils apt-transport-https curl git \
        gnupg-agent software-properties-common debsums unattended-upgrades \
        build-essential python3 python3-pip
}

# Enable automatic updates
configure_auto_updates() {
    echo "Configuring unattended upgrades..."
    apt-get install unattended-upgrades -y
    dpkg-reconfigure -plow unattended-upgrades
    echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
    echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
}

# Harden password policies
harden_password_policy() {
    echo "Setting password policies..."
    apt-get install libpam-cracklib -y
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs

    sed -i '/pam_unix.so/s/$/ remember=5 minlen=8/' /etc/pam.d/common-password
    sed -i '/pam_cracklib.so/s/$/ ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
}

# Implement account lockout policy
set_account_lockout() {
    echo "Setting account lockout policy..."
    if ! grep -q "pam_tally2" /etc/pam.d/common-auth; then
        echo "auth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail" >> /etc/pam.d/common-auth
    fi
}

# Remove unauthorized users and groups
audit_users_groups() {
    echo "Auditing users and groups..."
    for user in user1 user2; do
        if id "$user" &>/dev/null; then
            userdel -r "$user"
            echo "Removed unauthorized user: $user"
        fi
    done
    
    for user in $(awk -F: '($3 == 0) {print $1}' /etc/passwd); do
        if [ "$user" != "root" ]; then
            passwd -l "$user"
            echo "Locked non-root UID 0 user: $user"
        fi
    done
}

# Disable unwanted services
audit_services() {
    echo "Auditing services..."
    unwanted_services=(
        "telnet" "rsh-server" "rlogin" "rexec"
        "xinetd" "vsftpd" "ftp" "netcat" "nfs"
    )
    for service in "${unwanted_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            systemctl stop "$service"
            systemctl disable "$service"
            echo "Disabled service: $service"
        fi
    done
}

# Enable and configure UFW firewall
configure_firewall() {
    echo "Configuring firewall..."
    apt-get install ufw -y
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# Detect and remove backdoors
backdoor_detection() {
    echo "Detecting backdoors..."
    ss -ln | grep -v '127.0.0.1' | awk '{print $4}' | cut -d: -f2 | sort -u > open_ports.txt
    while read -r port; do
        lsof -i :"$port" > "port_${port}_info.txt"
    done < open_ports.txt
}

# Verify package integrity
verify_package_integrity() {
    echo "Verifying package integrity..."
    apt-get install debsums -y
    debsums -s
}

# Start full system hardening and package installation
system_update
install_packages
configure_auto_updates
harden_password_policy
set_account_lockout
audit_users_groups
audit_services
configure_firewall
backdoor_detection
verify_package_integrity

echo "System hardening and package installation complete."
