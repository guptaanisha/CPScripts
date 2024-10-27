# Get a list of non-critical services
Get-Service | Where-Object { $_.Status -ne 'Stopped' -and $_.StartType -eq 'Manual' -or $_.StartType -eq 'Disabled' } | Sort-Object Status
