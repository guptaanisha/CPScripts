#!/bin/sh


############### SCRIPT TO HAANDEN DEBIAN / UBUNTU SYSTEMS #######################

echo "Securing System"
echo -e "\nproc     /proc     proc     defaults,hidepid=2     0     0" | tee -a /etc/fstab >/dev/null 2>&1
sed -i -r -e "s/^(password\s+requisite\s+pam_pwquality.so)(.*)$/# \1\2 \n\1 retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoschec /" /etc/pam.d/common-password
sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/5000/1000000/g' /etc/login.defs
sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/5000/1000000/g' /etc/login.defs
sed -i '/PASS_MAX_DAYS/s/99999/180/g' /etc/login.defs
sed -i '/PASS_MIN_DAYS/s/0/1/g' /etc/login.defs
sed -i '/PASS_WARN_AGE/s/7/28/g' /etc/login.defs
sed -i '/UMASK/s/022/027/g' /etc/login.defs
sed -i '/# SHA_CRYPT_MAX_ROUNDS/s/#//g' /etc/login.defs
sed -i '/# SHA_CRYPT_MIN_ROUNDS/s/#//g' /etc/login.defs

echo "HRNGDEVICE=/dev/urandom" | tee -a /etc/default/rng-tools >/dev/null 2>&1
systemctl restart rng-tools.service >/dev/null 2>&1
systemctl enable rng-tools.service >/dev/null 2>&1

systemctl restart auditd >/dev/null 2>&1
systemctl enable auditd >/dev/null 2>&1

#getIni "START_COREDUMP" "END_COREDUMP" --- CHECK AND UPDATE
#printf "%s" "$output" | tee -a /etc/security/limits.conf >/dev/null 2>&1


# Kernel hardening --- CHECK IF NEEDED
echo "kernel.dmesg_restrict = 1" >/etc/sysctl.d/50-dmesg-restrict.conf 2>/dev/null
echo 'fs.suid_dumpable = 0' >/etc/sysctl.d/50-kernel-restrict.conf 2>/dev/null
echo "kernel.exec-shield = 2" >/etc/sysctl.d/50-exec-shield.conf 2>/dev/null
echo "kernel.randomize_va_space=2" >/etc/sysctl.d/50-rand-va-space.conf 2>/dev/null
echo "dev.tty.ldisc_autoload = 0" >/etc/sysctl.d/50-ldisc-autoload.conf 2>/dev/null
echo "fs.protected_fifos = 2" >/etc/sysctl.d/50-protected-fifos.conf 2>/dev/null
echo "kernel.core_uses_pid = 1" >/etc/sysctl.d/50-core-uses-pid.conf 2>/dev/null
echo "kernel.kptr_restrict = 2" >/etc/sysctl.d/50-kptr-restrict.conf 2>/dev/null
echo "kernel.sysrq = 0" >/etc/sysctl.d/50-sysrq.conf 2>/dev/null
echo "kernel.unprivileged_bpf_disabled = 1" >/etc/sysctl.d/50-unprivileged-bpf.conf 2>/dev/null
echo "kernel.yama.ptrace_scope = 1" >/etc/sysctl.d/50-ptrace-scope.conf 2>/dev/null
echo "net.core.bpf_jit_harden = 2" >/etc/sysctl.d/50-bpf-jit-harden.conf 2>/dev/null
###############################################

# Network hardening ######
echo 'net.ipv4.tcp_timestamps = 0' >/etc/sysctl.d/50-net-stack.conf 2>/dev/null
#Stop DDOS by disaabling syn attack
echo 'net.ipv4.tcp_syncookies = 1' >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
echo "net.ipv4.conf.all.accept_source_route = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
echo "net.ipv4.conf.all.accept_redirects = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
echo "net.ipv4.conf.all.log_martians = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
echo "net.ipv4.conf.all.rp_filter = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
echo "net.ipv4.conf.all.send_redirects = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
echo "net.ipv4.conf.default.accept_source_route = 0" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null
echo "net.ipv4.conf.default.log_martians = 1" >>/etc/sysctl.d/50-net-stack.conf 2>/dev/null


# FS hardening
echo "fs.protected_hardlinks = 1" >/etc/sysctl.d/50-fs-hardening.conf 2>/dev/null
echo "fs.protected_symlinks = 1" >>/etc/sysctl.d/50-fs-hardening.conf 2>/dev/null


sysctl -p >/dev/null 2>&1
# Disable uncommon filesystems
echo "install cramfs /bin/true" >/etc/modprobe.d/uncommon-fs.conf
echo "install freevxfs /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
echo "install jffs2 /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
echo "install hfs /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
echo "install hfsplus /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
echo "install squashfs /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
echo "install udf /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
echo "install fat /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
echo "install vfat /bin/true" >>/etc/modprobe.d/uncommon-fs.conf
echo "install gfs2 /bin/true" >>/etc/modprobe.d/uncommon-fs.conf

# Disable uncommon network protocols
echo "install dccp /bin/true" >/etc/modprobe.d/uncommon-net.conf
echo "install sctp /bin/true" >>/etc/modprobe.d/uncommon-net.conf
echo "install rds /bin/true" >>/etc/modprobe.d/uncommon-net.conf
echo "install tipc /bin/true" >>/etc/modprobe.d/uncommon-net.conf

# Disable Firewire
echo "install firewire-core /bin/true" >/etc/modprobe.d/firewire.conf
echo "install firewire-ohci /bin/true" >>/etc/modprobe.d/firewire.conf
echo "install firewire-sbp2 /bin/true" >>/etc/modprobe.d/firewire.conf

# Disable Bluetooth
echo "install bluetooth " >/etc/modprobe.d/bluetooth.conf

# Disable uncommon sound drivers
echo "install snd-usb-audio /bin/true" >/etc/modprobe.d/uncommon-sound.conf
echo "install snd-usb-caiaq /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
echo "install snd-usb-us122l /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
echo "install snd-usb-usx2y /bin/true" >>/etc/modprobe.d/uncommon-sound.conf
echo "install snd-usb-audio /bin/true" >>/etc/modprobe.d/uncommon-sound.conf

# Disable uncommon input drivers --- OPTIONAL
echo "install joydev /bin/true" >/etc/modprobe.d/uncommon-input.conf
echo "install pcspkr /bin/true" >>/etc/modprobe.d/uncommon-input.conf
echo "install serio_raw /bin/true" >>/etc/modprobe.d/uncommon-input.conf
echo "install snd-rawmidi /bin/true" >>/etc/modprobe.d/uncommon-input.conf
echo "install snd-seq-midi /bin/true" >>/etc/modprobe.d/uncommon-input.conf
echo "install snd-seq-oss /bin/true" >>/etc/modprobe.d/uncommon-input.conf
echo "install snd-seq /bin/true" >>/etc/modprobe.d/uncommon-input.conf
echo "install snd-seq-device /bin/true" >>/etc/modprobe.d/uncommon-input.conf
echo "install snd-timer /bin/true" >>/etc/modprobe.d/uncommon-input.conf
echo "install snd /bin/true" >>/etc/modprobe.d/uncommon-input.conf

# Remove telnet
apt-get -y --purge remove telnet nis ntpdate >/dev/null 2>&1

# File permissions
chown root:root /etc/grub.conf >/dev/null 2>&1
chown -R root:root /etc/grub.d >/dev/null 2>&1
chmod og-rwx /etc/grub.conf >/dev/null 2>&1
chmod og-rwx /etc/grub.conf >/dev/null 2>&1
chmod -R og-rwx /etc/grub.d >/dev/null 2>&1
chown root:root /boot/grub2/grub.cfg >/dev/null 2>&1
chmod og-rwx /boot/grub2/grub.cfg >/dev/null 2>&1
chown root:root /boot/grub/grub.cfg >/dev/null 2>&1
chmod og-rwx /boot/grub/grub.cfg >/dev/null 2>&1
chmod 0700 /home/* >/dev/null 2>&1
chmod 0644 /etc/passwd
chmod 0644 /etc/group
chmod -R 0600 /etc/cron.hourly
chmod -R 0600 /etc/cron.daily
chmod -R 0600 /etc/cron.weekly
chmod -R 0600 /etc/cron.monthly
chmod -R 0600 /etc/cron.d
chmod -R 0600 /etc/crontab
chmod -R 0600 /etc/shadow
chmod 750 /etc/sudoers.d
chmod -R 0440 /etc/sudoers.d/*
chmod 0600 /etc/ssh/sshd_config
chmod 0750 /usr/bin/w
chmod 0750 /usr/bin/who
chmod 0700 /etc/sysctl.conf
chmod 644 /etc/motd
chmod 0600 /boot/System.map-* >/dev/null 2>&1
#depmod -a >/dev/null 2>&1
#update-initramfs -u >/dev/null 2>&1

#Load new sysctl settings
sudo sysctl --system
echo "System secured successfully"

echo "Setting up Fail2ban"
output=$(sed -n "/START_F2B_SSH/,/END_F2B_SSH/{ /START_F2B_SSH/n; /END_F2B_SSH/!p }" "./config.ini")
printf "%s" "$output" | tee /etc/fail2ban/jail.d/ssh.local >/dev/null 2>&1
rm -f /etc/fail2ban/jail.d/defaults-debian.conf
fail2ban-client start >/dev/null 2>&1
fail2ban-client reload >/dev/null 2>&1
fail2ban-client add sshd >/dev/null 2>&1
echo "Fail2ban configured successfully"


echo "Initializing AIDE"
aideinit -y -f >/dev/null 2>&1
echo "AIDE initialized successfully"


echo "Configuring unattended updates"
output=$(sed -n "/START_UNATTENDED_UPGRADES/,/END_UNATTENDED_UPGRADES/{ /START_UNATTENDED_UPGRADES/n; /END_UNATTENDED_UPGRADES/!p }" "./config.ini")
printf "%s" "$output" | tee /etc/apt/apt.conf.d/51custom-unattended-upgrades >/dev/null 2>&1
echo "Unattended upgrades configured successfully"
