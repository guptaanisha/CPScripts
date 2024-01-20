##### Update GPO for Audit Policies

# Define the audit categories
$auditCategories = @(
    "Account Management",
    "Logon/Logoff",
    "Object Access",
    "Policy Change",
    "Privilege Use",
    "Process Tracking",
    "System"
)

# Enable auditing for various categories using PowerShell
foreach ($category in $auditCategories) {
    $settingName = "Audit$($category -replace '/', '')"
    $settingPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\$settingName"

    # Create the registry key if it doesn't exist
    if (-not (Test-Path $settingPath)) {
        New-Item -Path $settingPath -Force | Out-Null
    }

    # Enable Success and Failure auditing
    Set-ItemProperty -Path $settingPath -Name "Success" -Value 1
    Set-ItemProperty -Path $settingPath -Name "Failure" -Value 1
}

# Force Group Policy update
gpupdate /force


auditpol /get /category:*
