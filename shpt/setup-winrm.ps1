<#
.SYNOPSIS
    Creates or repairs the WinRM HTTPS listener on one SharePoint server.

.RUN THIS SCRIPT ON
    Each SharePoint node, from an elevated Windows PowerShell 5.1 console.

.WHEN TO RUN
    - After the SharePoint GPO has applied and certificate auto-enrollment has completed.
    - As a manual repair tool when the listener or certificate binding is incorrect.

.NOTES
    This script does not modify Windows Firewall and does not run gpupdate.
#>

#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateRange(1,30)]
    [int]$CertificateAttempts = 6,

    [ValidateRange(1,300)]
    [int]$DelaySeconds = 20,

    [switch]$ForceCertificatePulse
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-ServerAuthenticationEku {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $eku = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
        Select-Object -First 1

    if ($null -eq $eku) { return $false }

    try {
        $parsed = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension -ArgumentList $eku,$eku.Critical
        foreach ($usage in $parsed.EnhancedKeyUsages) {
            if ([string]$usage.Value -eq '1.3.6.1.5.5.7.3.1') { return $true }
        }
    }
    catch {
        $text = $eku.Format($false)
        if ($text -match '1\.3\.6\.1\.5\.5\.7\.3\.1' -or $text -match 'Server Authentication') {
            return $true
        }
    }

    return $false
}

function Get-CertificateDnsNames {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $names = @()
    try {
        foreach ($item in @($Certificate.DnsNameList)) {
            if ($null -ne $item -and $item.PSObject.Properties['Unicode']) {
                $names += [string]$item.Unicode
            }
        }
    }
    catch { }

    return @($names | ForEach-Object { $_.TrimEnd('.').ToLowerInvariant() } | Select-Object -Unique)
}

function Find-WinRmCertificate {
    param([Parameter(Mandatory)][string]$Fqdn)

    $now = Get-Date
    return Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            if (-not $_.HasPrivateKey -or $_.NotBefore -gt $now -or $_.NotAfter -le $now) { return $false }
            if (-not (Test-ServerAuthenticationEku -Certificate $_)) { return $false }

            $dnsNames = @(Get-CertificateDnsNames -Certificate $_)
            $subjectCn = ''
            if ($_.Subject -match '(?:^|,\s*)CN=([^,]+)') {
                $subjectCn = $Matches[1].TrimEnd('.').ToLowerInvariant()
            }

            return (($dnsNames -contains $Fqdn) -or ($subjectCn -eq $Fqdn))
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
}

Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

$computerSystem = Get-CimInstance Win32_ComputerSystem
if (-not $computerSystem.PartOfDomain) {
    throw 'This computer is not domain joined.'
}

$fqdn = ('{0}.{1}' -f $computerSystem.DNSHostName,$computerSystem.Domain).TrimEnd('.').ToLowerInvariant()
Write-Host "Target FQDN: $fqdn"

if ($ForceCertificatePulse) {
    Write-Host 'Requesting a certificate auto-enrollment pulse...'
    & certutil.exe -pulse | Out-Null
}

$certificate = $null
for ($attempt = 1; $attempt -le $CertificateAttempts -and $null -eq $certificate; $attempt++) {
    $certificate = Find-WinRmCertificate -Fqdn $fqdn
    if ($null -eq $certificate -and $attempt -lt $CertificateAttempts) {
        Write-Host "No suitable certificate yet; waiting $DelaySeconds seconds (attempt $attempt of $CertificateAttempts)..."
        Start-Sleep -Seconds $DelaySeconds
    }
}

if ($null -eq $certificate) {
    throw "No valid LocalMachine certificate with Server Authentication and DNS name '$fqdn' was found."
}

$thumbprint = $certificate.Thumbprint.Replace(' ','').ToUpperInvariant()
Write-Host "Certificate: $thumbprint"
Write-Host "Expires:     $($certificate.NotAfter)"

Import-Module Microsoft.WSMan.Management -ErrorAction SilentlyContinue
$httpsListeners = @(
    Get-WSManInstance -ResourceURI 'winrm/config/Listener' -Enumerate -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.Transport -eq 'HTTPS' }
)

$matchingListener = $httpsListeners | Where-Object {
    $thumbProperty = $_.PSObject.Properties['CertificateThumbprint']
    $hostProperty = $_.PSObject.Properties['Hostname']

    $existingThumbprint = if ($null -ne $thumbProperty) {
        ([string]$thumbProperty.Value).Replace(' ','').ToUpperInvariant()
    }
    else { '' }

    $existingHostname = if ($null -ne $hostProperty) {
        ([string]$hostProperty.Value).TrimEnd('.').ToLowerInvariant()
    }
    else { '' }

    $existingThumbprint -eq $thumbprint -and $existingHostname -eq $fqdn
} | Select-Object -First 1

if ($null -eq $matchingListener) {
    foreach ($listener in $httpsListeners) {
        Remove-WSManInstance `
            -ResourceURI 'winrm/config/Listener' `
            -SelectorSet @{ Address=[string]$listener.Address; Transport='HTTPS' } `
            -ErrorAction SilentlyContinue
    }

    New-WSManInstance `
        -ResourceURI 'winrm/config/Listener' `
        -SelectorSet @{ Address='*'; Transport='HTTPS' } `
        -ValueSet @{ Hostname=$fqdn; CertificateThumbprint=$thumbprint; Enabled=$true } `
        -ErrorAction Stop | Out-Null

    Restart-Service -Name WinRM -Force
    Write-Host 'WinRM HTTPS listener created or repaired.' -ForegroundColor Green
}
else {
    Write-Host 'WinRM HTTPS listener already matches the desired certificate and hostname.' -ForegroundColor Green
}

winrm enumerate winrm/config/listener