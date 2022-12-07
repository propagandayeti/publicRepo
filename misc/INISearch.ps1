# Define the path to the INI file
$iniFilePath = "C:\path\to\ini\file.ini"

# Read the INI file into a variable
$iniContent = Get-Content $iniFilePath

# Check if the entry exists in the INI file
if ($iniContent -notmatch "^thisentry=1$") {
    # If the entry doesn't exist, add it to the end of the file
    Add-Content $iniFilePath "thisentry=1"
}
