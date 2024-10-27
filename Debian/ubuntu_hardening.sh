#!/bin/bash

# Capture the start time
start_time=$(date +%s)

# Function to update and upgrade the system
system_update() {
    echo "Updating system..."
    apt-get update && apt-get -y upgrade
}

# Function to install necessary packages
install_packages() {
    echo "Installing necessary security packages..."
    apt-get install -y \
        ufw fail2ban apparmor apparmor-utils apt-transport-https curl git \
        gnupg-agent software-properties-common debsums unattended-upgrades \
        build-essential python3 python3-pip libpam-cracklib
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
    # Modify /etc/login.defs for password expiration
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs

    # Ensure PAM password complexity
    sed -i '/pam_unix.so/s/$/ remember=5 minlen=8/' /etc/pam.d/common-password
    sed -i '/pam_cracklib.so/s/$/ ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
}

# Set up account lockout policy
set_account_lockout() {
    echo "Setting account lockout policy..."
    if ! grep -q "pam_tally2" /etc/pam.d/common-auth; then
        echo "auth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail" >> /etc/pam.d/common-auth
    fi
}

# Set up UFW (Uncomplicated Firewall)
configure_firewall() {
    echo "Configuring UFW..."
    apt-get install ufw -y
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# Secure SSH configuration
secure_ssh() {
    echo "Securing SSH configuration..."
    sed -i 's/#Port 22/Port 2200/' /etc/ssh/sshd_config
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# Enable Fail2Ban to prevent brute force attacks
enable_fail2ban() {
    echo "Configuring Fail2Ban..."
    systemctl enable fail2ban
    systemctl start fail2ban
}

# Enable AppArmor to restrict applications
enable_apparmor() {
    echo "Enabling AppArmor..."
    systemctl enable apparmor
    systemctl start apparmor
}

# Verify package integrity with debsums
verify_package_integrity() {
    echo "Verifying package integrity..."
    apt-get install debsums -y
    debsums -s
}

# Disable unwanted services
disable_unwanted_services() {
    echo "Disabling unnecessary services..."
    systemctl disable cups
    systemctl stop cups
    systemctl disable avahi-daemon
    systemctl stop avahi-daemon
}

# Set filesystem mount options for security
secure_filesystem() {
    echo "Securing filesystem mount options..."
    sed -i 's/errors=remount-ro/errors=remount-ro,noexec,nosuid,nodev/' /etc/fstab
    mount -o remount,ro,noexec,nosuid,nodev /
}

# Remove unnecessary packages
remove_unnecessary_packages() {
    echo "Removing unnecessary packages..."
    apt-get purge -y xinetd inetutils-telnet inetutils-ftp rsh-client rsh-redone-client talk telnet ftp
    apt-get autoremove -y
}

# Start hardening the system
system_update
install_packages
configure_auto_updates
harden_password_policy
set_account_lockout
configure_firewall
secure_ssh
enable_fail2ban
enable_apparmor
verify_package_integrity
disable_unwanted_services
secure_filesystem
remove_unnecessary_packages

# Capture the end time
end_time=$(date +%s)

# Calculate the duration
execution_time=$((end_time - start_time))

# Print the total execution time
echo "System hardening complete. Time taken: $execution_time seconds."
