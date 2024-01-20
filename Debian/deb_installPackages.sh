#!/bin/sh

echo "Updating system"
apt-get -y update
sudo apt upgrade chromium
sudo apt upgrade libreoffice

apt-get -y install apt-transport-https ca-certificates host gnupg lsb-release >/dev/null 2>&1
echo "System updated successfully"

if ! dpkg -l | grep -q '^ii.*clamav'; then
        echo "ClamAV is not installed."
        echo "Installing Clamav"
        sudo apt-get install -y clamav clamav-freshclam clamav-daemon >/dev/null 2>&1
        echo "Clamav installed successfully"
        echo "Backing up Clamav configuration files"
        sudo cp -pr --archive "/etc/clamav/clamd.conf" "/etc/clamav/clamd.conf"-COPY-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
        echo "Clamav configuration files backed up successfully"
fi


if ! dpkg -l | grep -q '^ii.*lynis'; then
        echo "Installing Lynis"
        curl -s https://packages.cisofy.com/keys/cisofy-software-public.key | apt-key add - >/dev/null 2>&1
        echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | tee /etc/apt/sources.list.d/cisofy-lynis.list >/dev/null 2>&1
        apt-get -y update >/dev/null 2>&1
        apt-get -y install lynis host >/dev/null 2>&1
        echo "Lynis installed successfully"
        echo  "Updating Lynis database"
        lynis update info >/dev/null 2>&1
        echo "Lynis database updated successfully"
        echo "Running Lynis audit for base score (this can take a while)"
        lynis audit system --quiet --report-file /tmp/systemaudit-base-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
        base_score="$(grep hardening_index /tmp/systemaudit-base-"$(date +"%m-%d-%Y")" | cut -d"=" -f2)" >/dev/null 2>&1
        echo "Lynis audit completed with a Score of ${base_score}"
fi

echo "Installing required packages"
apt-get -y install rkhunter libpam-google-authenticator ufw fail2ban auditd audispd-plugins rsyslog chkrootkit libpam-pwquality net-tools curl unattended-upgrades apt-l
echo "Packages installed successfully"


if ! dpkg -l | grep -q '^ii.*Aide'; then
    echo "Installing AIDE"
    apt-get -y install aide aide-common >/dev/null 2>&1
    echo "AIDE installed successfully"
    echo "Backing up AIDE configuration files"
    sudo cp -pr --archive "/etc/aide" "/etc/aide"-COPY-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
    sudo cp -pr --archive "/etc/default/aide" "/etc/defaut/aide"-COPY-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
    echo "AIDE configuration files backed up successfully"
    echo "Configuring AIDE (this can take a while)"
    sed -i '/#CRON_DAILY_RUN=yes/s/#//g' /etc/default/aide >/dev/null 2>&1
    aideinit -y -f >/dev/null 2>&1
    echo "AIDE configured successfully"
fi

echo "Backing up configuration files"
sudo cp -pr --archive "/etc/fstab" "/etc/fstab"-COPY-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
sudo cp -pr --archive "/etc/pam.d/common-password" "/etc/pam.d/common-password"-COPY-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
sudo cp -pr --archive "/etc/pam.d/sshd" "/etc/pam.d/sshd"-COPY-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
sudo cp -pr --archive "/etc/chkrootkit.conf" "/etc/chkrootkit.conf"-COPY-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
sudo cp -pr --archive "/etc/ssh/shhd_config" "/etc/ssh/sshd_config"-COPY-"$(date +"%m-%d-%Y")" >/dev/null 2>&1
echo "Configuration files backed up successfully"
