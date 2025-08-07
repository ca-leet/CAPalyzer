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

.PARAMETER OutFile
(Optional) Path to save output report as text file.

.EXAMPLE
.\CAPalyzer.ps1 -CAPFile .\graphrunner_output.txt -ConfigFile .\recommended_caps.json

.NOTES
Created by [Your Name or Team], 2025.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Path to CAP export file (from GraphRunner)")]
    [string]$CAPFile,

    [Parameter(Mandatory = $true, HelpMessage = "Path to JSON file containing recommended CAPs")]
    [string]$ConfigFile,

    [Parameter(Mandatory = $false, HelpMessage = "Path to save output report as text file")]
    [string]$OutFile
)

function Write-Log {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    if ($script:OutFile) {
        $script:outputBuffer += $Message
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Invoke-CAPalyzer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CAPFile,
        [Parameter(Mandatory = $true)]
        [string]$ConfigFile,
        [Parameter(Mandatory = $false)]
        [string]$OutFile
    )
    if ($OutFile) { $script:outputBuffer = @() }

    # Define policy aliases for name mapping
    $policyAliases = @{
        "Require multifactor authentication for admins" = @(
            "Microsoft-managed: Multifactor authentication for admins accessing Microsoft Admin Portals",
            "Multifactor authentication for admins accessing Microsoft Admin Portals",
            "MFA for admin portal access",
            "Admin MFA policy",
            "Require MFA for all Admins"
        )
        "Require multifactor authentication for admin portals" = @(
            "Microsoft-managed: Multifactor authentication for admins accessing Microsoft Admin Portals",
            "Multifactor authentication for admins accessing Microsoft Admin Portals",
            "Require MFA for all Admins"
        )
        "Require multifactor authentication for all users" = @(
            "Microsoft-managed: Multifactor authentication for per-user multifactor authentication users",
            "MFA for all users",
            "Global MFA policy"
        )
        "Require compliant device" = @(
            "Require Compliant Devices for Access",
            "Compliant device policy",
            "Device compliance requirement"
        )
        "Require compliant or hybrid joined device or MFA for all users" = @(
            "Require Compliant Devices for Access",
            "Compliant device or MFA policy"
        )
        "Block high sign-in risk" = @(
            "Microsoft-managed: Multifactor authentication and reauthentication for risky sign-ins",
            "Risky sign-in policy",
            "High risk sign-in block"
        )
        "Securing security info registration" = @(
            "SSPR Conditional Access",
            "Security info registration policy",
            "SSPR policy"
        )
        # Add more mappings as needed
        # "Another recommended policy" = @("Alternative name 1", "Alternative name 2")
    }

    # Load recommended CAPs
    $recommendedCAPs = Get-Content $ConfigFile | ConvertFrom-Json

    # Read entire export file and split by policy divider
    $raw = Get-Content $CAPFile -Raw -ErrorAction Stop
    $blocks = $raw -split '={10,}'  # Adjust separator pattern if needed

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

    # Check for missing policies using aliases
    $missing = @()
    foreach ($rec in $recommendedCAPs) {
        $aliases = @($rec)
        if ($policyAliases.ContainsKey($rec)) {
            $aliases += $policyAliases[$rec]
        }
        
        $found = $false
        foreach ($alias in $aliases) {
            if ($foundDisplayNames -contains $alias) {
                $found = $true
                break
            }
        }
        
        if (-not $found) {
            $missing += $rec
        }
    }

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
        Write-Log "    (Note: Manual validation recommended - policies may exist under different names)" "Cyan"
        $missing | ForEach-Object { Write-Log "  - $_" }
    } else {
        Write-Log "`nAll recommended policies appear to be present." "Green"
    }

    Write-Log "`n==========================================`n" "Cyan"

    if ($OutFile) {
        $script:outputBuffer | Set-Content -Path $OutFile
    }
}

# Only run if not dot-sourced
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-CAPalyzer -CAPFile $CAPFile -ConfigFile $ConfigFile -OutFile $OutFile
}
