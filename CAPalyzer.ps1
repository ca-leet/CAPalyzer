<#
.SYNOPSIS
CAPalyzer - Conditional Access Policy analysis tool for GraphRunner exports.

.DESCRIPTION
Analyzes Conditional Access Policies exported via GraphRunner for common security posture weaknesses.
Detects:
- Policies still in "Reporting" mode
- Excluded users or groups
- Missing recommended CAPs from a supplied config file

.PARAMETER CAPFile
Path to the exported CAP file (e.g., from GraphRunner).

.PARAMETER ConfigFile
Path to the recommended CAPs JSON file.

.EXAMPLE
.\CAPalyzer.ps1 -CAPFile .\graphrunner_output.txt -ConfigFile .\recommended_caps.json

.NOTES
Created by [Your Name or Team], 2025.
#>

param (
    [Parameter(Mandatory = $true, HelpMessage = "Path to CAP export file (from GraphRunner)")]
    [string]$CAPFile,

    [Parameter(Mandatory = $true, HelpMessage = "Path to JSON file containing recommended CAPs")]
    [string]$ConfigFile,

    [Parameter(Mandatory = $false, HelpMessage = "Path to save output report as text file")]
    [string]$OutFile
)

param (
    [string]$CAPFile = "cap_export.txt",
    [string]$ConfigFile = "recommended_caps.json"
)

# Load recommended CAPs
$recommendedCAPs = Get-Content $ConfigFile | ConvertFrom-Json

# Read entire export file and split by policy divider
$raw = Get-Content $CAPFile -Raw -ErrorAction Stop
$blocks = $raw -split "={10,}"  # Adjust separator pattern if needed

$reporting = @()
$exclusions = @()
$foundDisplayNames = @()

foreach ($block in $blocks) {
    if (-not $block.Trim()) { continue }
    $lines = $block -split "`r?`n"
    $name = ($lines | Where-Object { $_ -match "^Display Name:" }) -replace "^Display Name:\s*", ""
    $state = ($lines | Where-Object { $_ -match "^Policy State:" }) -replace "^Policy State:\s*", ""
    $foundDisplayNames += $name

    if ($state -eq "Reporting") {
        $reporting += $name
    }

    # Extract Exclude lines: check under Users and Groups
    $exclLines = $lines | Where-Object { $_ -match "Exclude\s*:" } 
    foreach ($idx in ($lines | Where-Object { $_ -match "Exclude\s*:" } | ForEach-Object { [Array]::IndexOf($lines, $_) })) {
        for ($i = $idx + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^\s+(Users|Groups)\s*:\s*(.+)") {
                $type = $Matches[1]
                $ids = $Matches[2]
                $exclusions += [PSCustomObject]@{ Policy = $name; Type = $type; IDs = $ids }
            } elseif ($lines[$i].Trim() -eq "") { break }
        }
    }
}

$missing = $recommendedCAPs | Where-Object { $_ -notin $foundDisplayNames }

# Report
Write-Log "`n=== Conditional Access Weakness Report ===`n" "Cyan"

if ($reporting) {
    Write-Log "[!] Policies in REPORTING mode:" "Yellow"
    $reporting | ForEach-Object { Write-Log "  - $_" }
} else {
    Write-Log "No policies are in Reporting mode." "Green"
}

if ($exclusions) {
    Write-Log "`n[!] Excluded Users/Groups:" "Yellow"
    $exclusions | ForEach-Object {
        Write-Log "  - Policy: $($_.Policy) | Type: $($_.Type) | IDs: $($_.IDs)"
    }
} else {
    Write-Log "`nNo explicit exclusions found." "Green"
}

if ($missing) {
    Write-Log "`n[!] Missing Recommended Policies:" "Yellow"
    $missing | ForEach-Object { Write-Log "  - $_" }
} else {
    Write-Log "`nAll recommended policies appear to be present." "Green"
}

Write-Log "`n==========================================`n" "Cyan"
