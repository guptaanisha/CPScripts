##### Disable the Guest account
([adsi]"WinNT://./Guest,user").UserFlags = 2

################

##### Disable Anonymous SID Enumeration
# Define the registry key path
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

# Create or update the registry key to disable anonymous SID enumeration
Set-ItemProperty -Path $registryPath -Name "RestrictAnonymous" -Value 1

# Define the registry key path
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

# Enable Network Level Authentication (NLA)
Set-ItemProperty -Path $registryPath -Name "UserAuthentication" -Value 1

# Restart the Remote Desktop Services to apply changes
Restart-Service -Name TermService -Force


#############
##### Disable Remote Assistance

# Define the registry key path for Remote Assistance
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"

# Create the registry key if it doesn't exist
New-Item -Path $registryPath -Force | Out-Null

# Set the registry value to disable Remote Assistance
Set-ItemProperty -Path $registryPath -Name "fAllowToGetHelp" -Value 0

# Force Group Policy update
gpupdate /force
