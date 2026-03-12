<#
.SYNOPSIS
This PowerShell script will prevent attachments from being downloaded from RSS feeds.
Purpose: STIG/Policy hardening - disable enclosure downloads for IE Feeds

.NOTES
  Author          : Elizabeth Harnisch
  LinkedIn        : linkedin.com/in/elizabeth-harnisch/
  GitHub          : github.com/elizabeth-a-h
  Date Created : 2026-03-12
  Last Modified : 2026-03-12
  Version : 1.0
  CVEs : N/A
  Plugin IDs : N/A
  STIG-ID : WN11-CC-000295

  Requirements : Run as Administrator (writes to HKLM)
  Reboot Required : No (policy refresh may be required in managed environments)
  GPO/MDM Note : If a Domain GPO/MDM manages this setting, it may overwrite local changes.

.TESTED ON
  Date(s) Tested : 
  Tested By : 
  Systems Tested : 
  PowerShell Ver. : 

.USAGE
  Run elevated (Administrator).
  Example syntax:
  .\Set-DisableEnclosureDownload.ps1 -Verbose
#>

# Define the registry path and value information
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
$ValueName  = "DisableEnclosureDownload"
$ValueType  = "DWord" # REG_DWORD
$ValueData  = 1

# Check if the registry path exists, and create it if it doesn't
if (-not (Test-Path $RegistryPath)) {
  New-Item -Path $RegistryPath -Force | Out-Null
  Write-Verbose "Registry path '$RegistryPath' created." -Verbose
}

# Check if the value already exists
if ($null -eq (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue)) {
  # Create the registry value
  New-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -PropertyType $ValueType -Force | Out-Null
  Write-Verbose "Registry value '$ValueName' created with value '$ValueData'." -Verbose
} else {
  # Value exists, check if it is the correct value.
  $CurrentValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName).$ValueName

  if ($CurrentValue -ne $ValueData) {
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData
    Write-Verbose "Registry value '$ValueName' updated to '$ValueData'." -Verbose
  } else {
    Write-Verbose "Registry value '$ValueName' already exists and is equal to '$ValueData'." -Verbose
  }
}
