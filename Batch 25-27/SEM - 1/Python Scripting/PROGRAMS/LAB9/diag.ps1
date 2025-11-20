# diag.ps1
# PowerShell script for local diagnostics (cross-platform)
# Demonstrates advanced functions, param block, output processing, and ByRef argument usage

function Invoke-LocalDiagnostics {
    [CmdletBinding()]
    param (
        # ByRef argument allows function to update caller's hashtable
        [ref]$SummaryHash
    )

    # Cross-platform computer name
    $computerName = [System.Net.Dns]::GetHostName()

    # Get basic OS details for macOS/Linux
    try {
        # Get-ComputerInfo not supported on macOS
        $osName      = (uname -s)
        $osVersion   = (sw_vers -productVersion)
        $architecture = (uname -m)
        $osInfo = [PSCustomObject]@{
            OsName        = $osName
            OsArchitecture = $architecture
            OsVersion     = $osVersion
        }
    } catch {
        # Fallback values if commands fail
        $osInfo = [PSCustomObject]@{
            OsName        = "Unknown"
            OsArchitecture = "Unknown"
            OsVersion     = "Unknown"
        }
    }

    # Get top 5 CPU-consuming processes on the system
    $processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, CPU, Id

    # Create a custom object to hold diagnostic results
    $result = [PSCustomObject]@{
        Computer     = $computerName                       # Machine name (cross-platform)
        OS           = $osInfo.OsName                      # OS Name
        Architecture = $osInfo.OsArchitecture              # OS Architecture
        Version      = $osInfo.OsVersion                   # OS Version
        TopProcesses = $processes                          # Top processes collection
    }

    # Prepare or update the summary hash table, using -ByRef for direct update
    $summary = $SummaryHash.Value
    $summary[$computerName] = @{
        OS        = $result.OS
        LastBoot  = "N/A"                                 # macOS: last boot not handled here
        ProcCount = $result.TopProcesses.Count
    }
    $SummaryHash.Value = $summary

    # Return diagnostics object for inspection or output
    return $result
}

# Instructions:
# 1. In pwsh, load this script: . ./diag.ps1
# 2. Prepare an empty summary hash table: $summary = @{}
# 3. Call the function: $diagnostic = Invoke-LocalDiagnostics -SummaryHash ([ref]$summary)
# 4. View results:
#    $diagnostic | Format-List
#    $summary | Format-Table
