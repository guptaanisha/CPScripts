# Comprehensive Windows Hardening Script
# Author: Merged from multiple sources, with additional security best practices
# Purpose: To harden Windows systems by applying security settings, enforcing policies, disabling insecure services, and more.

# Set the ErrorActionPreference to stop on critical errors
$ErrorActionPreference = "Stop"

# 1. Disable SMBv1 (Outdated and insecure protocol)
Write-Host "Disabling SMBv1 protocol..."
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# 2. Enable Windows Defender Real-Time Protection and Enhanced Settings
Write-Host "Enabling Windows Defender real-time protection and cloud-based protection..."
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced # Enable cloud-delivered protection
Set-MpPreference -SubmitSamplesConsent 1  # Automatically send malware samples to Microsoft

# 3. Run a Full Windows Defender Scan
#Write-Host "Running a full Windows Defender scan..."
#Start-MpScan -ScanType FullScan

# 4. Enforce Strong Password Policies
Write-Host "Enforcing strong password policies..."
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg) -replace 'MinimumPasswordLength = \d+', 'MinimumPasswordLength = 12' | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg
Remove-Item C:\Windows\Temp\secpol.cfg

# 5. Enforce Password Complexity Requirements
Write-Host "Enforcing password complexity requirements..."
$complexity = @{
    'PasswordComplexity' = 1; # Enable complexity (requires a mix of characters)
    'MinimumPasswordAge' = 1; # 1 day minimum age before password change
    'MaximumPasswordAge' = 90; # 90 days before password must be changed
    'LockoutThreshold' = 5; # Lock account after 5 invalid attempts
    'LockoutDuration' = 30; # Lockout duration for 30 minutes
    'LockoutObservationWindow' = 30 # Observation window for 30 minutes
}
foreach ($key in $complexity.Keys) {
    secedit /export /cfg C:\Windows\Temp\secpol.cfg
    (Get-Content C:\Windows\Temp\secpol.cfg) -replace "$key = \d+", "$key = $($complexity[$key])" | Set-Content C:\Windows\Temp\secpol.cfg
    secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg
}
Remove-Item C:\Windows\Temp\secpol.cfg

# 6. Enable Audit Policies for Logon and Object Access Events
Write-Host "Enabling audit policy for logon and object access events..."
AuditPol /set /category:"Logon/Logoff" /success:enable /failure:enable
AuditPol /set /category:"Object Access" /success:enable /failure:enable

# 7. Update Group Policy for Audit Policies
Write-Host "Updating Group Policy audit policies..."
$auditCategories = @(
    "Account Management",
    "Logon/Logoff",
    "Object Access",
    "Policy Change",
    "Privilege Use",
    "Process Tracking",
    "System"
)

foreach ($category in $auditCategories) {
    $settingName = "Audit$($category -replace '/', '')"
    $settingPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\$settingName"
    
    if (-not (Test-Path $settingPath)) {
        New-Item -Path $settingPath -Force | Out-Null
    }

    Set-ItemProperty -Path $settingPath -Name "Success" -Value 1
    Set-ItemProperty -Path $settingPath -Name "Failure" -Value 1
}

gpupdate /force

# 8. Configure Firewall to Block Inbound Connections by Default
Write-Host "Configuring Windows Firewall to block inbound connections by default..."
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block


# Fixing SSH Firewall Rule Configuration
Write-Host "Configuring SSH Firewall Rule..."

# Remove the existing rule if necessary (optional step)
Remove-NetFirewallRule -DisplayName "OpenSSH" -ErrorAction SilentlyContinue

# Create new inbound and outbound rules for SSH (Port 22)
New-NetFirewallRule -DisplayName "OpenSSH Inbound" -Protocol TCP -LocalPort 22 -Action Allow -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "OpenSSH Outbound" -Protocol TCP -LocalPort 22 -Action Allow -Enabled True -Direction Outbound

# 10. Disable Unnecessary Services
Write-Host "Disabling unnecessary services..."
$services = @("RemoteRegistry", "Telnet", "LanmanServer", "LanmanWorkstation", "Fax")

foreach ($service in $services) {
    # Check if the service exists
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        Set-Service -Name $service -StartupType Disabled
        Stop-Service -Name $service -Force
        Write-Host "$service disabled."
    } else {
        Write-Host "Service $service not found, skipping..."
    }
}

# 11. Disable Guest Account and SID
Write-Host "Disabling Guest account and SID..."
Disable-LocalUser -Name "Guest"
Write-Host "Guest account disabled."

# 12. Unregister Unnecessary Scheduled Tasks
Write-Host "Unregistering unnecessary scheduled tasks..."
$tasks = @("*Bluetooth*", "*Location*", "*Maps*", "*UPnP*", "*Plug and Play*", "*Windows Error Reporting*")
foreach ($task in $tasks) {
    Unregister-ScheduledTask -TaskPath $task -ErrorAction SilentlyContinue
}

# 13. Disable AutoRun and AutoPlay
Write-Host "Disabling AutoRun and AutoPlay..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWORD -Force

# 14. Restrict Anonymous Access
Write-Host "Restricting anonymous access..."
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -PropertyType DWORD -Force

# 15. Disable LM Hash Storage
Write-Host "Disabling LM hash storage..."
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -PropertyType DWORD -Force

# 16. Check for Secure Boot configuration
Write-Host "Checking for Secure Boot configuration..."

# Check if the system supports UEFI
if (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty BIOSVersion -ErrorAction SilentlyContinue | Select-String -Pattern "UEFI") {
    try {
        Confirm-SecureBootUEFI
    } catch {
        Write-Host "Secure Boot is not enabled or not supported on this platform."
    }
} else {
    Write-Host "UEFI is not supported on this platform, skipping Secure Boot check..."
}

# 17. Disable LLMNR (Link-Local Multicast Name Resolution)
Write-Host "Disabling LLMNR..."

# Check if the DNSClient registry path exists, if not, create it
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
    Write-Host "Creating registry path for DNSClient..."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force | Out-Null
}

# Now set the Disable LLMNR property
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force
Write-Host "LLMNR disabled."

# 18. Hardening Remote Desktop with NLA
Write-Host "Hardening Remote Desktop..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1

# 19. Disable Unused Windows Features
Write-Host "Disabling unused Windows features..."

# Function to disable a feature if it exists
function Disable-WindowsFeatureIfInstalled {
    param (
        [string]$featureName
    )

    $feature = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq $featureName }

    if ($feature -and $feature.State -ne "Disabled") {
        Disable-WindowsOptionalFeature -FeatureName $featureName -Online -NoRestart
        Write-Host "$featureName has been disabled."
    } else {
        Write-Host "$featureName is not available or already disabled, skipping..."
    }
}

# Attempt to disable specific features
Disable-WindowsFeatureIfInstalled -featureName "XPSViewer"
Disable-WindowsFeatureIfInstalled -featureName "WindowsMediaPlayer"


# 20. Configure User Account Control (UAC)
Write-Host "Configuring User Account Control (UAC)..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -PropertyType DWORD -Force

# 21. Configuring Local Account Privileges
Write-Host "Configuring local account privileges..."
secedit /export /cfg C:\Windows\Temp\localrights.cfg
(Get-Content C:\Windows\Temp\localrights.cfg) -replace 'SeRemoteInteractiveLogonRight = .*', 'SeRemoteInteractiveLogonRight = Administrators' | Set-Content C:\Windows\Temp\localrights.cfg
secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\localrights.cfg
Remove-Item C:\Windows\Temp\localrights.cfg

# 22. Enable BitLocker Encryption
Write-Host "Enabling BitLocker on all available drives..."

# Check if the Enable-BitLocker cmdlet is available
if (Get-Command -Name Enable-BitLocker -ErrorAction SilentlyContinue) {
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256
    Write-Host "BitLocker enabled on C: drive."
} else {
    Write-Host "BitLocker is not available on this system, skipping BitLocker encryption."
}

# 23. Disable Windows Remote Assistance
Write-Host "Disabling Windows Remote Assistance..."

# Check if the Remote Assistance registry path exists
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance") {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
    Write-Host "Windows Remote Assistance disabled."
} else {
    Write-Host "Remote Assistance is not available on this system, skipping..."
}

# 24. Enforce Secure LDAP Signing (Domain Controllers only)
Write-Host "Enforcing secure LDAP signing..."

# Check if the system is a Domain Controller
if ((Get-WmiObject Win32_ComputerSystem).DomainRole -eq 5) {
    # Check if the NTDS Parameters registry path exists, create it if needed
    if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters")) {
        Write-Host "NTDS Parameters registry path does not exist, skipping secure LDAP signing..."
    } else {
        # Set the LDAP signing requirement
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -PropertyType DWORD -Force
        Write-Host "Secure LDAP signing enforced."
    }
} else {
    Write-Host "This system is not a Domain Controller, skipping LDAP signing configuration..."
}


# 25. Enforce SMB Message Signing
Write-Host "Enforcing SMB message signing..."
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -PropertyType DWORD -Force

# 26. Configure Log Retention and Size Limits
Write-Host "Configuring log retention and size limits..."
wevtutil sl Security /rt:true /ms:5120

# 27. Hardening PowerShell environment
Write-Host "Hardening PowerShell environment..."

# Check if the PowerShell registry path exists, create it if needed
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell")) {
    Write-Host "Creating registry path for PowerShell policies..."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "PowerShell" -Force | Out-Null
}

# Set the PowerShell logging and execution policies
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force
Write-Host "PowerShell Script Block Logging enabled."

# 28. Check for and Install Windows Updates Automatically
Write-Host "Checking for Windows updates and installing them automatically..."
Install-WindowsUpdate -AcceptAll -AutoReboot

Write-Host "Windows updates installed successfully, system may reboot."

Write-Host "Windows hardening script completed."
