#!/bin/bash

# Full whitelist of known essential services for Ubuntu (adjust as necessary)
WHITELIST=(
    # System services
    "systemd-journald.service"
    "systemd-udevd.service"
    "systemd-timesyncd.service"
    "dbus.service"
    "polkit.service"
    "rsyslog.service"
    "cron.service"
    "snapd.service"
    "multipathd.service"
    "systemd-logind.service"

    # Networking services
    "networking.service"
    "NetworkManager.service"
    "networkd-dispatcher.service"
    "wpa_supplicant.service"
    "ModemManager.service"
    "ssh.service"

    # Security services
    "ufw.service"                    # Firewall
    "apparmor.service"               # Mandatory access control
    "fail2ban.service"               # Protection against brute-force attacks (optional but recommended)
    "clamav-daemon.service"          # Antivirus (optional, if installed)

    # Disk and file system services
    "udev.service"
    "systemd-remount-fs.service"
    "systemd-fsckd.service"

    # Hardware-related services
    "accounts-daemon.service"
    "bluetooth.service"              # Bluetooth (optional, remove if not needed)
    "cups.service"                   # Printing system (optional, remove if not needed)

    # Optional desktop services (for GUI installations)
    "gdm.service"                    # GNOME Display Manager (for GUI login)
    "lightdm.service"                # Light Display Manager (alternative to GNOME, adjust based on your system)
    "avahi-daemon.service"           # Network discovery (for printers and shared resources, optional)
    "whoopsie.service"               # Error reporting
    "udisks2.service"                # Disk management
    "accounts-daemon.service"        # User account management
    "colord.service"                 # Color management (for graphical systems)

    # Power management and laptop services (for laptops)
    "acpid.service"                  # Power management (optional, usually needed on laptops)
    "thermald.service"               # Thermal management (optional)
    "upower.service"                 # Power management (for battery status)

    # Miscellaneous services
    "unattended-upgrades.service"    # Automatic security updates
    "apt-daily.service"              # Daily APT package update checks
    "snapd.service"                  # Snap package management
    "plymouth.service"               # Boot splash screen
    "rngd.service"                   # Random number generator daemon
)

# Define output file
NON_WHITELISTED_FILE="non_whitelisted_services.txt"

# Clear the file if it exists
> "$NON_WHITELISTED_FILE"

# Function to check if a service is in the whitelist
is_whitelisted() {
    local service=$1
    for good_service in "${WHITELIST[@]}"; do
        if [[ "$good_service" == "$service" ]]; then
            return 0
        fi
    done
    return 1
}

# Get a list of all active services
ACTIVE_SERVICES=$(systemctl list-units --type=service --state=active --no-pager --no-legend | awk '{print $1}')

# Loop through each active service
for service in $ACTIVE_SERVICES; do
    # Check if the service is in the whitelist
    if is_whitelisted "$service"; then
        echo "$service is whitelisted and will be retained."
    else
        # Add non-whitelisted service to the list file
        echo "$service" >> "$NON_WHITELISTED_FILE"
        echo "$service is not in the whitelist and has been added to $NON_WHITELISTED_FILE"
    fi
done

# Generate command to remove/stop non-whitelisted services
echo "The following services are not in the whitelist:"
cat "$NON_WHITELISTED_FILE"

echo
echo "To stop and disable non-whitelisted services, you can run the following commands manually:"
echo "sudo systemctl stop \$(cat $NON_WHITELISTED_FILE) && sudo systemctl disable \$(cat $NON_WHITELISTED_FILE)"
