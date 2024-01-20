# Start a full scan
Start-MpScan -ScanType FullScan

# Wait for the scan to complete
while ((Get-MpComputerStatus).ScanInProgress) {
    Start-Sleep -Seconds 10
}

# Display the scan results
Get-MpThreatDetection
