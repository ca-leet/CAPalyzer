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
        "Block legacy auth" = @(
            "Block legacy authentication",
            "Legacy authentication policy",
            "Disable legacy protocols"
        )
        "Require phishing resistant MFA for admins" = @(
            "Phishing-resistant MFA for admins",
            "Require strong authentication for admins",
            "Require phishing resistant multifactor authentication for admins"
        )
        "Require MFA auth strength for all users" = @(
            "Require multifactor authentication for all users",
            "MFA for all users",
            "Global MFA policy",
            "Require authentication strength for all users"
        )
        "Require MFA auth strength for all guests" = @(
            "Require multifactor authentication for all guests",
            "MFA for all guests",
            "Require authentication strength for all guests"
        )
        "Secure security info registration" = @(
            "Securing security info registration",
            "SSPR Conditional Access",
            "Security info registration policy"
        )
        "Require MFA for risky sign on" = @(
            "Block high sign-in risk",
            "Risky sign-in policy",
            "Microsoft-managed: Multifactor authentication and reauthentication for risky sign-ins",
            "Require multifactor authentication for risky sign-ins"
        )
        "Require password change for risky users" = @(
            "Block high user risk",
            "High user risk policy",
            "Require password reset for risky users"
        )
        "Require auth strength for device registration" = @(
            "Device registration MFA",
            "MFA for device registration",
            "Require authentication strength for device registration"
        )
        "Require device compliance" = @(
            "Require compliant device",
            "Require Compliant Devices for Access",
            "Device compliance requirement"
        )
        "Restrict device code flow and authentication transfer" = @(
            "Restrict device code flow",
            "Restrict authentication transfer",
            "Block device code flow",
            "Block authentication transfer"
        )
    }

    # Load recommended CAPs
    $recommendedCAPs = Get-Content $ConfigFile | ConvertFrom-Json

    # Read entire export file
    $raw = Get-Content $CAPFile -Raw -ErrorAction Stop
    
    $reporting = @()
    $exclusions = @()
    $foundDisplayNames = @()

    # Try to parse as JSON first
    try {
        $jsonData = $raw | ConvertFrom-Json -ErrorAction Stop
        
        # Handle Microsoft Graph API format and other structures
        # Check for Microsoft Graph API format with 'value' property
        if ($jsonData.value) {
            $policies = $jsonData.value
        } elseif ($jsonData -is [Array]) {
            $policies = $jsonData
        } else {
            $policies = @($jsonData)
        }
        
        foreach ($policy in $policies) {
            if ($policy.displayName) {
                $name = $policy.displayName
                $state = $policy.state
                $foundDisplayNames += $name

                # Check for various reporting state variations (case-insensitive)
                if ($state) {
                    $reportingStates = @("Reporting", "enabledForReportingButNotEnforced", "reporting", "enabledForReporting", "reportingOnly")
                    $stateLower = $state.ToLower()
                    $reportingStatesLower = $reportingStates | ForEach-Object { $_.ToLower() }
                    if ($reportingStatesLower -contains $stateLower) {
                        $reporting += $name
                    }
                }

                # Extract exclusions from JSON structure
                if ($policy.conditions -and $policy.conditions.users -and $policy.conditions.users.excludeUsers) {
                    $exclusions += [PSCustomObject]@{ Policy = $name; Type = "Users"; IDs = ($policy.conditions.users.excludeUsers -join ", ") }
                }
                if ($policy.conditions -and $policy.conditions.users -and $policy.conditions.users.excludeGroups) {
                    $exclusions += [PSCustomObject]@{ Policy = $name; Type = "Groups"; IDs = ($policy.conditions.users.excludeGroups -join ", ") }
                }
            }
        }
    }
    catch {
        # Fall back to text-based parsing
        $blocks = $raw -split '={10,}'  # Adjust separator pattern if needed

        foreach ($block in $blocks) {
            if (-not $block.Trim()) { continue }
            $lines = $block -split "`r?`n"
            $name = ($lines | Where-Object { $_ -match "^Display Name:" -or $_ -match "(?i)^(display\s*name|name):" } | Select-Object -First 1) -replace "(?i)^(display\s*name|name):\s*", ""
            $state = ($lines | Where-Object { $_ -match "^Policy State:" -or $_ -match "(?i)^(policy\s*state|state):" } | Select-Object -First 1) -replace "(?i)^(policy\s*state|state):\s*", ""
            $foundDisplayNames += $name

            # Check for various reporting state variations (case-insensitive)
            if ($state) {
                $reportingStates = @("Reporting", "enabledForReportingButNotEnforced", "reporting", "enabledForReporting", "reportingOnly")
                $stateLower = $state.ToLower()
                $reportingStatesLower = $reportingStates | ForEach-Object { $_.ToLower() }
                if ($reportingStatesLower -contains $stateLower) {
                    $reporting += $name
                }
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
    }

    # Check for missing policies using aliases (case-insensitive)
    $missing = @()
    $foundDisplayNamesLower = $foundDisplayNames | ForEach-Object { $_.ToLower() }
    
    foreach ($rec in $recommendedCAPs) {
        $aliases = @($rec)
        if ($policyAliases.ContainsKey($rec)) {
            $aliases += $policyAliases[$rec]
        }
        
        $found = $false
        foreach ($alias in $aliases) {
            $aliasLower = $alias.ToLower()
            if ($foundDisplayNamesLower -contains $aliasLower) {
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
        Write-Log "[!] Policies in Reporting mode:" "Yellow"
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
