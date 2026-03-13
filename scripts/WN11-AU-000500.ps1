<#
.SYNOPSIS
    This PowerShell script configures the system to ensure the maximum size of the 
    Windows Application event log is at least 32768 KB (32 MB) in accordance with Windows 11 STIG WN11-AU-000500.

.DESCRIPTION
    Creates the registry path if it does not exist and ensures the specified
    registry value is present and configured with the expected data required
    for Windows 11 STIG compliance. This remediation configures the maximum
    size of the Application event log.

.NOTES
    Author          : Elizabeth Harnisch
    LinkedIn        : https://www.linkedin.com/in/elizabeth-harnisch/
    GitHub          : https://github.com/elizabeth-a-h
    Date Created    : 2026-03-08
    Last Modified   : 2026-03-08
    Version         : 1.0

    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

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

    .\WN11-AU-000500.ps1 -Verbose
#>

[CmdletBinding()]
param()

# =========================
# CONFIGURATION
# =========================

$STIG         = "WN11-AU-000500"
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName    = "MaxSize"
$ValueType    = "DWord"
$ValueData    = 0x8000

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

    if ($CurrentValue -lt $ValueData) {

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

if ($VerifiedValue -ge $ValueData) {
    Write-Output "STIG ${STIG}: COMPLIANT"
}
else {
    Write-Output "STIG ${STIG}: NON-COMPLIANT"
}
