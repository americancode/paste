
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Tests whether a Windows server is ready for WinRM over HTTPS.

.DESCRIPTION
    Checks:
      - Domain membership and computer FQDN
      - Applied Group Policy
      - Certificate auto-enrollment policy
      - Enterprise CA discovery
      - Available certificate templates
      - Certificate enrollment event logs
      - Certificates in LocalMachine\My
      - Private key, validity, Server Authentication EKU, and hostname match
      - Existing WinRM listeners
      - WinRM service status
      - TCP 5986 listener
      - Windows Firewall rules for TCP 5986

    This script makes no configuration changes.
#>

[CmdletBinding()]
param(
    [string]$ExpectedGpoName = 'Servers - SharePoint',

    # Optional certificate template display name or short template name.
    [string]$ExpectedTemplateName = 'Ansible WinRM HTTPS',

    [int]$EventCount = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:Failures = 0
$script:Warnings = 0

function Write-Section {
    param([Parameter(Mandatory)][string]$Title)

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Pass {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([Parameter(Mandatory)][string]$Message)

    $script:Warnings++
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([Parameter(Mandatory)][string]$Message)

    $script:Failures++
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-Info {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host "[INFO] $Message"
}

function Get-ComputerFqdn {
    try {
        $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop

        if (-not $computerSystem.PartOfDomain) {
            Write-Fail 'The computer is not joined to an Active Directory domain.'
            return $null
        }

        Write-Pass "Computer is joined to domain '$($computerSystem.Domain)'."

        return '{0}.{1}' -f `
            $env:COMPUTERNAME.ToLowerInvariant(),
            $computerSystem.Domain.ToLowerInvariant()
    }
    catch {
        Write-Fail "Could not determine domain membership: $($_.Exception.Message)"
        return $null
    }
}

function Test-ServerAuthenticationEku {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $serverAuthenticationOid = '1.3.6.1.5.5.7.3.1'

    foreach ($extension in $Certificate.Extensions) {
        if ($extension.Oid.Value -ne '2.5.29.37') {
            continue
        }

        try {
            $ekuExtension =
                [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension

            if (
                $ekuExtension.EnhancedKeyUsages |
                Where-Object Value -EQ $serverAuthenticationOid
            ) {
                return $true
            }
        }
        catch {
            return $false
        }
    }

    return $false
}

function Get-CertificateDnsNames {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $names = @()

    try {
        $names = @(
            $Certificate.DnsNameList |
            ForEach-Object {
                $_.Unicode
            }
        )
    }
    catch {
        # DnsNameList may not be available on older PowerShell/.NET versions.
    }

    return $names
}

function Test-CertificateHostname {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory)]
        [string]$Fqdn
    )

    $requiredName = $Fqdn.ToLowerInvariant()
    $dnsNames = @(Get-CertificateDnsNames -Certificate $Certificate)

    foreach ($dnsName in $dnsNames) {
        $candidate = $dnsName.ToLowerInvariant()

        if ($candidate -eq $requiredName) {
            return $true
        }

        if ($candidate.StartsWith('*.')) {
            $suffix = $candidate.Substring(1)

            if (
                $requiredName.EndsWith($suffix) -and
                $requiredName.Split('.').Count -eq $candidate.Split('.').Count
            ) {
                return $true
            }
        }
    }

    if ($Certificate.Subject -match '(?i)(?:^|,\s*)CN=([^,]+)') {
        $commonName = $Matches[1].Trim().ToLowerInvariant()

        if ($commonName -eq $requiredName) {
            return $true
        }
    }

    return $false
}

function Test-AppliedGpo {
    param([Parameter(Mandatory)][string]$GpoName)

    Write-Section 'Applied computer Group Policy'

    try {
        $output = & gpresult.exe /R /SCOPE COMPUTER 2>&1
        $text = $output -join [Environment]::NewLine

        if ($LASTEXITCODE -ne 0) {
            Write-Warn "gpresult exited with code $LASTEXITCODE."
        }

        if ($text -match [regex]::Escape($GpoName)) {
            Write-Pass "GPO '$GpoName' is listed in computer policy results."
        }
        else {
            Write-Fail "GPO '$GpoName' was not found in computer policy results."
        }

        $output | ForEach-Object {
            Write-Host "  $_"
        }
    }
    catch {
        Write-Fail "Could not run gpresult: $($_.Exception.Message)"
    }
}

function Test-AutoEnrollmentPolicy {
    Write-Section 'Certificate auto-enrollment policy'

    $path =
        'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment'

    if (-not (Test-Path $path)) {
        Write-Fail "Auto-enrollment policy registry path does not exist: $path"
        return
    }

    try {
        $settings = Get-ItemProperty -Path $path -ErrorAction Stop
        $aePolicy = $settings.AEPolicy

        Write-Info "AEPolicy value: $aePolicy"

        if ([int]$aePolicy -gt 0) {
            Write-Pass 'Computer certificate auto-enrollment policy is enabled.'
        }
        else {
            Write-Fail 'AEPolicy is present but does not enable auto-enrollment.'
        }

        $settings |
            Format-List |
            Out-String |
            Write-Host
    }
    catch {
        Write-Fail "Could not read auto-enrollment policy: $($_.Exception.Message)"
    }
}

function Test-EnterpriseCaDiscovery {
    Write-Section 'Enterprise Certification Authority discovery'

    try {
        $output = & certutil.exe -config - -ping 2>&1
        $exitCode = $LASTEXITCODE

        $output | ForEach-Object {
            Write-Host "  $_"
        }

        if ($exitCode -eq 0) {
            Write-Pass 'At least one enterprise CA was discovered and contacted.'
        }
        else {
            Write-Fail "Enterprise CA discovery or connectivity failed, exit code $exitCode."
        }
    }
    catch {
        Write-Fail "Could not execute certutil CA discovery: $($_.Exception.Message)"
    }
}

function Test-CertificateTemplates {
    param([string]$TemplateName)

    Write-Section 'Available certificate templates'

    try {
        $output = & certutil.exe -template 2>&1
        $exitCode = $LASTEXITCODE
        $text = $output -join [Environment]::NewLine

        if ($exitCode -ne 0) {
            Write-Fail "certutil -template failed with exit code $exitCode."

            $output | ForEach-Object {
                Write-Host "  $_"
            }

            return
        }

        if ([string]::IsNullOrWhiteSpace($TemplateName)) {
            Write-Pass 'Certificate template enumeration succeeded.'
        }
        elseif ($text -match [regex]::Escape($TemplateName)) {
            Write-Pass "Template '$TemplateName' is visible to this computer."
        }
        else {
            Write-Fail @"
Template '$TemplateName' was not found in the templates visible to this computer.
Confirm that the template is published and that this computer or its security
group has Read and Enroll permissions.
"@
        }

        $matchingLines = $output |
            Where-Object {
                $_ -match 'Template' -or
                $_ -match [regex]::Escape($TemplateName)
            }

        if ($matchingLines) {
            $matchingLines | ForEach-Object {
                Write-Host "  $_"
            }
        }
    }
    catch {
        Write-Fail "Could not enumerate certificate templates: $($_.Exception.Message)"
    }
}

function Show-EnrollmentEvents {
    param([int]$MaximumEvents)

    Write-Section 'Recent certificate enrollment events'

    $logs = @(
        'Microsoft-Windows-CertificateServicesClient-AutoEnrollment/Operational'
        'Microsoft-Windows-CertificateServicesClient-CertEnroll/Operational'
    )

    foreach ($log in $logs) {
        Write-Host ''
        Write-Host "Log: $log" -ForegroundColor White

        try {
            $logInfo = Get-WinEvent -ListLog $log -ErrorAction Stop

            if (-not $logInfo.IsEnabled) {
                Write-Warn "Event log '$log' is disabled."
                continue
            }

            $events = Get-WinEvent `
                -LogName $log `
                -MaxEvents $MaximumEvents `
                -ErrorAction Stop |
                Sort-Object TimeCreated -Descending

            if (-not $events) {
                Write-Warn "No events were found in '$log'."
                continue
            }

            $events |
                Select-Object `
                    TimeCreated,
                    Id,
                    LevelDisplayName,
                    @{
                        Name = 'Message'
                        Expression = {
                            ($_.Message -replace '\s+', ' ').Trim()
                        }
                    } |
                Format-Table -Wrap -AutoSize
        }
        catch {
            Write-Warn "Could not read '$log': $($_.Exception.Message)"
        }
    }
}

function Test-MachineCertificates {
    param([Parameter(Mandatory)][string]$Fqdn)

    Write-Section 'Local Computer personal certificates'

    $now = Get-Date
    $certificates = @(Get-ChildItem Cert:\LocalMachine\My)

    if (-not $certificates) {
        Write-Fail 'Cert:\LocalMachine\My contains no certificates.'
        return @()
    }

    Write-Info "Required WinRM hostname: $Fqdn"
    Write-Info "Certificates found: $($certificates.Count)"

    $results = foreach ($certificate in $certificates) {
        $dnsNames = @(Get-CertificateDnsNames -Certificate $certificate)
        $hasServerAuthentication =
            Test-ServerAuthenticationEku -Certificate $certificate
        $hostnameMatches =
            Test-CertificateHostname -Certificate $certificate -Fqdn $Fqdn
        $currentlyValid =
            $certificate.NotBefore -le $now -and
            $certificate.NotAfter -gt $now

        $suitable =
            $certificate.HasPrivateKey -and
            $currentlyValid -and
            $hasServerAuthentication -and
            $hostnameMatches

        [pscustomobject]@{
            Suitable             = $suitable
            Subject              = $certificate.Subject
            Issuer               = $certificate.Issuer
            HasPrivateKey        = $certificate.HasPrivateKey
            CurrentlyValid       = $currentlyValid
            ServerAuthentication = $hasServerAuthentication
            HostnameMatches      = $hostnameMatches
            DNSNames             = $dnsNames -join ', '
            NotBefore            = $certificate.NotBefore
            NotAfter             = $certificate.NotAfter
            Thumbprint           = $certificate.Thumbprint
        }
    }

    $results |
        Sort-Object `
            @{Expression='Suitable';Descending=$true},
            @{Expression='NotAfter';Descending=$true} |
        Format-List
        $suitableCertificates = @(
            $results |
            Where-Object Suitable
        )

    if ($suitableCertificates.Count -gt 0) {
        Write-Pass "$($suitableCertificates.Count) suitable WinRM HTTPS certificate(s) found."
    }
    else {
        Write-Fail 'No certificate satisfies every WinRM HTTPS requirement.'

        Write-Host ''
        Write-Host 'Requirement summary:' -ForegroundColor Yellow

        foreach ($result in $results) {
            Write-Host "Certificate: $($result.Thumbprint)"

            if (-not $result.HasPrivateKey) {
                Write-Host '  - Missing private key' -ForegroundColor Red
            }

            if (-not $result.CurrentlyValid) {
                Write-Host '  - Certificate is expired or not yet valid' -ForegroundColor Red
            }

            if (-not $result.ServerAuthentication) {
                Write-Host '  - Missing Server Authentication EKU' -ForegroundColor Red
            }

            if (-not $result.HostnameMatches) {
                Write-Host "  - SAN/CN does not match $Fqdn" -ForegroundColor Red
            }
        }
    }

    return $results
}

function Test-WinRmConfiguration {
    Write-Section 'WinRM service and listeners'

    try {
        $service = Get-Service WinRM -ErrorAction Stop

        Write-Info "WinRM service status: $($service.Status)"
        Write-Info "WinRM service start type: $($service.StartType)"

        if ($service.Status -eq 'Running') {
            Write-Pass 'WinRM service is running.'
        }
        else {
            Write-Fail 'WinRM service is not running.'
        }

        if ($service.StartType -eq 'Automatic') {
            Write-Pass 'WinRM service startup type is Automatic.'
        }
        else {
            Write-Warn "WinRM service startup type is '$($service.StartType)'."
        }
    }
    catch {
        Write-Fail "Could not inspect the WinRM service: $($_.Exception.Message)"
    }

    try {
        $output = & winrm.exe enumerate winrm/config/listener 2>&1
        $text = $output -join [Environment]::NewLine

        $output | ForEach-Object {
            Write-Host "  $_"
        }

        if ($text -match '(?im)^\s*Transport\s*=\s*HTTPS\s*$') {
            Write-Pass 'A WinRM HTTPS listener exists.'
        }
        else {
            Write-Fail 'No WinRM HTTPS listener exists.'
        }
    }
    catch {
        Write-Fail "Could not enumerate WinRM listeners: $($_.Exception.Message)"
    }

    try {
        $tcpListeners = @(
            Get-NetTCPConnection `
                -LocalPort 5986 `
                -State Listen `
                -ErrorAction SilentlyContinue
        )

        if ($tcpListeners.Count -gt 0) {
            Write-Pass 'A process is listening on TCP 5986.'

            $tcpListeners |
                Format-Table `
                    LocalAddress,
                    LocalPort,
                    State,
                    OwningProcess `
                    -AutoSize
        }
        else {
            Write-Fail 'No process is listening on TCP 5986.'
        }
    }
    catch {
        Write-Fail "Could not inspect TCP 5986: $($_.Exception.Message)"
    }
}

function Test-WinRmFirewall {
    Write-Section 'Windows Firewall rules for TCP 5986'

    try {
        $matchingRules = foreach (
            $rule in Get-NetFirewallRule `
                -Enabled True `
                -Direction Inbound `
                -Action Allow `
                -ErrorAction Stop
        ) {
            $portFilters = @(
                $rule |
                Get-NetFirewallPortFilter `
                    -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Protocol -eq 'TCP' -and
                    (
                        $_.LocalPort -eq '5986' -or
                        $_.LocalPort -eq 'Any'
                    )
                }
            )

            if ($portFilters) {
                $addressFilter = $rule |
                    Get-NetFirewallAddressFilter `
                        -ErrorAction SilentlyContinue

                [pscustomobject]@{
                    DisplayName   = $rule.DisplayName
                    Enabled       = $rule.Enabled
                    Profile       = $rule.Profile
                    LocalPort     = ($portFilters.LocalPort -join ', ')
                    RemoteAddress = ($addressFilter.RemoteAddress -join ', ')
                }
            }
        }

        $matchingRules = @($matchingRules)

        if ($matchingRules.Count -gt 0) {
            Write-Pass 'At least one enabled inbound allow rule covers TCP 5986.'

            $matchingRules |
                Format-Table -Wrap -AutoSize
        }
        else {
            Write-Fail 'No enabled inbound allow firewall rule covers TCP 5986.'
        }
    }
    catch {
        Write-Fail "Could not inspect Windows Firewall rules: $($_.Exception.Message)"
    }
}

Write-Host ''
Write-Host 'WinRM HTTPS and AD CS readiness test' -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "Started:  $(Get-Date)"
Write-Host ''

$fqdn = Get-ComputerFqdn

Test-AppliedGpo -GpoName $ExpectedGpoName
Test-AutoEnrollmentPolicy
Test-EnterpriseCaDiscovery
Test-CertificateTemplates -TemplateName $ExpectedTemplateName
Show-EnrollmentEvents -MaximumEvents $EventCount

if ($fqdn) {
    $null = Test-MachineCertificates -Fqdn $fqdn
}

Test-WinRmConfiguration
Test-WinRmFirewall

Write-Section 'Final result'

Write-Host "Failures: $script:Failures"
Write-Host "Warnings: $script:Warnings"

if ($script:Failures -eq 0) {
    Write-Host ''
    Write-Pass 'The server appears ready for WinRM over HTTPS.'
    exit 0
}
else {
    Write-Host ''
    Write-Fail @"
The server is not ready for WinRM over HTTPS.

Review the failed checks above. If the only certificate-related failure is that
the expected template is unavailable or no suitable certificate exists, correct
the AD CS template publication and permissions, then run:

    gpupdate /force
    certutil -pulse

After enrollment completes, rerun this test.
"@

    exit 1
}
