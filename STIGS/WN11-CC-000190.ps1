<#
.SYNOPSIS
    This PowerShell script configures the system to disable AutoRun for all drive types in accordance with Windows 11 STIG WN11-CC-000190.

.DESCRIPTION
    Creates the registry path if it does not exist and ensures the specified
    registry value is present and configured with the expected data required
    for Windows 11 STIG compliance. This remediation implements the policy
    setting "Turn off AutoRun" for all drives.

.NOTES
    Author          : Elizabeth Harnisch
    LinkedIn        : https://www.linkedin.com/in/elizabeth-harnisch/
    GitHub          : https://github.com/elizabeth-a-h
    Date Created    : 2026-03-12
    Last Modified   : 2026-03-12
    Version         : 1.0

    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000190

    Requirements    : Run as Administrator (writes to HKLM)
    Reboot Required : No (policy refresh may be required in managed environments)
    GPO/MDM Note    : If a Domain GPO or MDM policy manages this setting, it may overwrite local registry changes.

.TESTED ON
    Date(s) Tested  :
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run the script in an elevated PowerShell session.

    Example syntax:

    .\WN11-CC-000190.ps1 -Verbose
#>

[CmdletBinding()]
param()

# =========================
# CONFIGURATION
# =========================

$STIG         = "WN11-CC-000190"
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ValueName    = "NoDriveTypeAutoRun"
$ValueType    = "DWord"
$ValueData    = 0xFF

# =========================
# ENSURE REGISTRY PATH EXISTS
# =========================

if (-not (Test-Path -Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
    Write-Verbose "Created registry path: $RegistryPath"
}

# =========================
# CHECK CURRENT VALUE
# =========================

$ExistingProperty = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue

if ($null -eq $ExistingProperty) {

    New-ItemProperty `
        -Path $RegistryPath `
        -Name $ValueName `
        -Value $ValueData `
        -PropertyType $ValueType `
        -Force | Out-Null

    Write-Verbose "Created registry value '$ValueName' with data '$ValueData'."
}
else {

    $CurrentValue = $ExistingProperty.$ValueName

    if ($CurrentValue -ne $ValueData) {

        Set-ItemProperty `
            -Path $RegistryPath `
            -Name $ValueName `
            -Value $ValueData

        Write-Verbose "Updated registry value '$ValueName' from '$CurrentValue' to '$ValueData'."
    }
    else {

        Write-Verbose "Registry value '$ValueName' already configured correctly."
    }
}

# =========================
# VERIFICATION
# =========================

$VerifiedValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName).$ValueName

if ($VerifiedValue -eq $ValueData) {
    Write-Output "STIG ${STIG}: COMPLIANT"
}
else {
    Write-Output "STIG ${STIG}: NON-COMPLIANT"
