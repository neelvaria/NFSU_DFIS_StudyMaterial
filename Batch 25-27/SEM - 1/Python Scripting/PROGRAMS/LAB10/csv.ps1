# csv.ps1
# PowerShell script that automates reading from and writing to CSV files
# Demonstrates param blocks, error handling, file I/O, and structured processing for cross-platform use

param(
    [string]$InputCsv = "./users.csv",                # Path to input CSV file
    [string]$OutputCsv = "./processed-users.csv",     # Path to output CSV file
    [string]$ErrorLog = "./errors.log"                # Path to error log file
)

# Remove output and error log files from previous runs, silencing errors if files do not exist
Remove-Item $OutputCsv, $ErrorLog -ErrorAction SilentlyContinue

try {
    # Check if the input file exists. If not, throw an error.
    if (-not (Test-Path $InputCsv)) {
        throw "Input CSV file '$InputCsv' not found."
    }
    
    # Import user data from CSV into array of objects
    $users = Import-Csv -Path $InputCsv
    $results = @()    # Initialize empty array to store result objects

    # Process each user record from the CSV
    foreach ($user in $users) {
        try {
            # Example transformation: build full name
            $fullName = "$($user.FirstName) $($user.LastName)"
            
            # Add processed info to results array
            $results += [PSCustomObject]@{
                Username = $user.Username
                FullName = $fullName
                Status   = "Processed"
            }
        }
        catch {
            # On error, record status and write error details to log
            $results += [PSCustomObject]@{
                Username = $user.Username
                FullName = ""
                Status   = "Error: $($_.Exception.Message)"
            }
            # Append error details to the error log file with date/time
            "`n[$(Get-Date)] Error processing '$($user.Username)': $($_.Exception.Message)" | Out-File -FilePath $ErrorLog -Append
        }
    }

    # Export processed results to new CSV file
    $results | Export-Csv -Path $OutputCsv -NoTypeInformation

    # Check if export was successful, throw exception if not
    if (!$?) {
        throw "Failed to write processed data to $OutputCsv"
    }
}
catch {
    # Top-level error capture, logs fatal script errors to error log file
    "[$(Get-Date)] Fatal script error: $($_.Exception.Message)" | Out-File -FilePath $ErrorLog -Append
}

# Show completion message with output and error log file info
Write-Host "Processing complete. Output: $OutputCsv, Errors (if any): $ErrorLog"
