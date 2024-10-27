# Define the root directory to search
$rootDirectory = "C:\Users"

# Define the media file extensions you want to search for
$mediaExtensions = "*.mp3", "*.mp4", "*.avi", "*.mov", "*.wmv", "*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp"

# Get all subdirectories under the root directory
$subDirectories = Get-ChildItem $rootDirectory -Directory -Recurse

# Loop through each subdirectory
foreach ($subDirectory in $subDirectories) {
    # Search for media files in the current subdirectory
    $mediaFiles = Get-ChildItem $subDirectory.FullName -Include $mediaExtensions

    # If media files are found, output the subdirectory path and the file names
    if ($mediaFiles.Count -gt 0) {
        Write-Host "Media files found in $($subDirectory.FullName):"
        foreach ($mediaFile in $mediaFiles) {
            Write-Host "  - $($mediaFile.Name)"
        }
    }
}
