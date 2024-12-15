Get-ChildItem -Path "C:\" -Recurse -File | ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA1
    if ($hash.Hash -eq "1234567890") {
        Write-Output $_.FullName
    }
}
