#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Tests whether a Windows Server target is ready for WinRM over HTTPS.

.DESCRIPTION
    Performs read-only diagnostic checks for:

      - Domain membership and computer FQDN
      - Applied computer Group Policy
      - Certificate auto-enrollment policy
      - Enterprise CA discovery
      - Certificate template visibility
      - Certificate enrollment event logs
      - Certificates in Cert:\LocalMachine\My
      - Private key presence
      - Certificate validity
      - Server Authentication EKU
      - SAN or subject CN hostname match
      - WinRM service
      - WinRM HTTPS listener
      - TCP port 5986 listener
      - Windows Firewall rules covering TCP 5986

    This script does not modify the system.

.NOTES
    Designed for Windows PowerShell 5.1.
#>

[CmdletBinding()]
param(
    [string]$ExpectedGpoName = 'Servers - SharePoint',

    [string]$ExpectedTemplateName = 'Ansible WinRM HTTPS',

    [ValidateRange(1, 500)]
    [int]$EventCount = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$script:Failures = 0
$script:Warnings = 0

function Write-Section {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Pass {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:Warnings++
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:Failures++
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-Info {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[INFO] $Message"
}

function Get-ComputerFqdn {
    try {
        $computerSystem = Get-CimInstance `
            -ClassName Win32_ComputerSystem `
            -ErrorAction Stop

        if (-not $computerSystem.PartOfDomain) {
            Write-Fail 'The computer is not joined to an Active Directory domain.'
            return $null
        }

        Write-Pass "Computer is joined to domain '$($computerSystem.Domain)'."

        $fqdn = '{0}.{1}' -f `
            $env:COMPUTERNAME.ToLowerInvariant(),
            $computerSystem.Domain.ToLowerInvariant()

        Write-Pass "Detected computer FQDN: $fqdn"

        return $fqdn
    }
    catch {
        Write-Fail "Could not determine domain membership: $($_.Exception.Message)"
        return $null
    }
}

function Get-CertificateDnsNames {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $names = @()

    try {
        if ($Certificate.PSObject.Properties.Name -contains 'DnsNameList') {
            foreach ($dnsName in $Certificate.DnsNameList) {
                if ($null -ne $dnsName) {
                    if (
                        $dnsName.PSObject.Properties.Name -contains 'Unicode' -and
                        -not [string]::IsNullOrWhiteSpace($dnsName.Unicode)
                    ) {
                        $names += [string]$dnsName.Unicode
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace([string]$dnsName)) {
                        $names += [string]$dnsName
                    }
                }
            }
        }
    }
    catch {
        # Continue to extension parsing below.
    }

    if ($names.Count -gt 0) {
        return @($names | Select-Object -Unique)
    }

    try {
        $sanExtension = $Certificate.Extensions |
            Where-Object {
                $_.Oid.Value -eq '2.5.29.17'
            } |
            Select-Object -First 1

        if ($null -ne $sanExtension) {
            $formattedSan = $sanExtension.Format($true)

            $matches = [regex]::Matches(
                $formattedSan,
                '(?im)(?:DNS Name=|DNS:)\s*([^,\r\n]+)'
            )

            foreach ($match in $matches) {
                $value = $match.Groups[1].Value.Trim()

                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    $names += $value
                }
            }
        }
    }
    catch {
        # Return any names already found.
    }

    return @($names | Select-Object -Unique)
}

function Test-ServerAuthenticationEku {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $serverAuthenticationOid = '1.3.6.1.5.5.7.3.1'
    $ekuExtensionOid = '2.5.29.37'

    $ekuExtension = $Certificate.Extensions |
        Where-Object {
            $_.Oid.Value -eq $ekuExtensionOid
        } |
        Select-Object -First 1

    if ($null -eq $ekuExtension) {
        return $false
    }

    try {
        $enhancedKeyUsageExtension =
            New-Object `
                System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension `
                -ArgumentList $ekuExtension, $ekuExtension.Critical

        foreach ($usage in $enhancedKeyUsageExtension.EnhancedKeyUsages) {
            if ($usage.Value -eq $serverAuthenticationOid) {
                return $true
            }
        }
    }
    catch {
        try {
            $formattedEku = $ekuExtension.Format($false)

            if (
                $formattedEku -match [regex]::Escape($serverAuthenticationOid) -or
                $formattedEku -match 'Server Authentication'
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

function Test-CertificateHostname {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory = $true)]
        [string]$Fqdn
    )

    $requiredName = $Fqdn.Trim().ToLowerInvariant()
    $dnsNames = @(Get-CertificateDnsNames -Certificate $Certificate)

    foreach ($dnsName in $dnsNames) {
        if ([string]::IsNullOrWhiteSpace($dnsName)) {
            continue
        }

        $candidate = $dnsName.Trim().ToLowerInvariant()

        if ($candidate -eq $requiredName) {
            return $true
        }

        if ($candidate.StartsWith('*.')) {
            $suffix = $candidate.Substring(1)

            $requiredLabelCount = $requiredName.Split('.').Count
            $candidateLabelCount = $candidate.Split('.').Count

            if (
                $requiredName.EndsWith($suffix) -and
                $requiredLabelCount -eq $candidateLabelCount
            ) {
                return $true
            }
        }
    }

    try {
        $commonName = $Certificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName,
            $false
        )

        if (
            -not [string]::IsNullOrWhiteSpace($commonName) -and
            $commonName.Trim().ToLowerInvariant() -eq $requiredName
        ) {
            return $true
        }
    }
    catch {
        # Fall back to parsing the subject.
    }

    if ($Certificate.Subject -match '(?i)(?:^|,\s*)CN=([^,]+)') {
        $subjectCommonName = $Matches[1].Trim().ToLowerInvariant()

        if ($subjectCommonName -eq $requiredName) {
            return $true
        }
    }

    return $false
}

function Test-AppliedGpo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName
    )

    Write-Section 'Applied computer Group Policy'

    try {
        $output = @(& gpresult.exe /R /SCOPE COMPUTER 2>&1)
        $exitCode = $LASTEXITCODE
        $text = $output -join [Environment]::NewLine

        if ($exitCode -ne 0) {
            Write-Warn "gpresult exited with code $exitCode."
        }

        if (
            -not [string]::IsNullOrWhiteSpace($GpoName) -and
            $text -match [regex]::Escape($GpoName)
        ) {
            Write-Pass "GPO '$GpoName' is listed in the computer policy results."
        }
        elseif ([string]::IsNullOrWhiteSpace($GpoName)) {
            Write-Warn 'No expected GPO name was supplied.'
        }
        else {
            Write-Fail "GPO '$GpoName' was not found in the computer policy results."
        }

        foreach ($line in $output) {
            Write-Host "  $line"
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

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Fail "Auto-enrollment policy registry path does not exist: $path"
        return
    }

    try {
        $settings = Get-ItemProperty `
            -LiteralPath $path `
            -ErrorAction Stop

        $aePolicyProperty = $settings.PSObject.Properties['AEPolicy']

        if ($null -eq $aePolicyProperty) {
            Write-Fail 'The AEPolicy registry value does not exist.'
            return
        }

        $aePolicy = [int]$aePolicyProperty.Value

        Write-Info "AEPolicy value: $aePolicy"

        if ($aePolicy -gt 0) {
            Write-Pass 'Computer certificate auto-enrollment policy is enabled.'
        }
        else {
            Write-Fail 'AEPolicy exists but is set to zero.'
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
        $output = @(& certutil.exe -config - -ping 2>&1)
        $exitCode = $LASTEXITCODE

        foreach ($line in $output) {
            Write-Host "  $line"
        }

        if ($exitCode -eq 0) {
            Write-Pass 'An enterprise CA was discovered and contacted.'
        }
        else {
            Write-Fail "Enterprise CA discovery failed with exit code $exitCode."
        }
    }
    catch {
        Write-Fail "Could not run certutil CA discovery: $($_.Exception.Message)"
    }
}

function Test-CertificateTemplates {
    param(
        [string]$TemplateName
    )

    Write-Section 'Available certificate templates'

    try {
        $output = @(& certutil.exe -template 2>&1)
        $exitCode = $LASTEXITCODE
        $text = $output -join [Environment]::NewLine

        if ($exitCode -ne 0) {
            Write-Fail "certutil -template failed with exit code $exitCode."

            foreach ($line in $output) {
                Write-Host "  $line"
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

Possible causes:
  - The template is not published on the issuing CA.
  - The computer does not have Read permission.
  - The computer does not have Enroll permission.
  - The supplied name differs from the template display name or template name.
"@
        }

        $matchingLines = @()

        foreach ($line in $output) {
            if (
                $line -match '(?i)template' -or
                (
                    -not [string]::IsNullOrWhiteSpace($TemplateName) -and
                    $line -match [regex]::Escape($TemplateName)
                )
            ) {
                $matchingLines += $line
            }
        }

        if ($matchingLines.Count -gt 0) {
            foreach ($line in $matchingLines) {
                Write-Host "  $line"
            }
        }
    }
    catch {
        Write-Fail "Could not enumerate certificate templates: $($_.Exception.Message)"
    }
}

function Show-EnrollmentEvents {
    param(
        [Parameter(Mandatory = $true)]
        [int]$MaximumEvents
    )

    Write-Section 'Recent certificate enrollment events'

    $logs = @(
        'Microsoft-Windows-CertificateServicesClient-AutoEnrollment/Operational',
        'Microsoft-Windows-CertificateServicesClient-CertEnroll/Operational'
    )

    foreach ($log in $logs) {
        Write-Host ''
        Write-Host "Log: $log" -ForegroundColor White

        try {
            $logInfo = Get-WinEvent `
                -ListLog $log `
                -ErrorAction Stop

            if (-not $logInfo.IsEnabled) {
                Write-Warn "Event log '$log' is disabled."
                continue
            }

            $events = @(
                Get-WinEvent `
                    -LogName $log `
                    -MaxEvents $MaximumEvents `
                    -ErrorAction Stop |
                Sort-Object -Property TimeCreated -Descending
            )

            if ($events.Count -eq 0) {
                Write-Warn "No events were found in '$log'."
                continue
            }

            $eventOutput = foreach ($event in $events) {
                $message = ''

                try {
                    $message = [string]$event.Message
                }
                catch {
                    $message = '<Unable to read event message>'
                }

                if ($null -eq $message) {
                    $message = ''
                }

                [pscustomobject]@{
                    TimeCreated      = $event.TimeCreated
                    Id               = $event.Id
                    LevelDisplayName = $event.LevelDisplayName
                    Message          = ($message -replace '\s+', ' ').Trim()
                }
            }

            $eventOutput |
                Format-Table -Wrap -AutoSize
        }
        catch {
            Write-Warn "Could not read '$log': $($_.Exception.Message)"
        }
    }
}

function Test-MachineCertificates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fqdn
    )

    Write-Section 'Local Computer personal certificates'

    $now = Get-Date

    try {
        $certificates = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop)
    }
    catch {
        Write-Fail "Could not read Cert:\LocalMachine\My: $($_.Exception.Message)"
        return @()
    }

    if ($certificates.Count -eq 0) {
        Write-Fail 'Cert:\LocalMachine\My contains no certificates.'
        return @()
    }

    Write-Info "Required WinRM hostname: $Fqdn"
    Write-Info "Certificates found: $($certificates.Count)"

    $results = @()

    foreach ($certificate in $certificates) {
        $dnsNames = @(Get-CertificateDnsNames -Certificate $certificate)

        $hasServerAuthentication =
            Test-ServerAuthenticationEku -Certificate $certificate

        $hostnameMatches =
            Test-CertificateHostname `
                -Certificate $certificate `
                -Fqdn $Fqdn

        $currentlyValid =
            ($certificate.NotBefore -le $now) -and
            ($certificate.NotAfter -gt $now)

        $hasPrivateKey = $false

        try {
            $hasPrivateKey = [bool]$certificate.HasPrivateKey
        }
        catch {
            $hasPrivateKey = $false
        }

        $suitable =
            $hasPrivateKey -and
            $currentlyValid -and
            $hasServerAuthentication -and
            $hostnameMatches

        $results += [pscustomobject]@{
            Suitable             = $suitable
            Subject              = $certificate.Subject
            Issuer               = $certificate.Issuer
            HasPrivateKey        = $hasPrivateKey
            CurrentlyValid       = $currentlyValid
            ServerAuthentication = $hasServerAuthentication
            HostnameMatches      = $hostnameMatches
            DNSNames             = ($dnsNames -join ', ')
            NotBefore            = $certificate.NotBefore
            NotAfter             = $certificate.NotAfter
            Thumbprint           = $certificate.Thumbprint
        }
    }

    $sortedResults = $results |
        Sort-Object -Property `
            @{
                Expression = 'Suitable'
                Descending = $true
            },
            @{
                Expression = 'NotAfter'
                Descending = $true
            }

    $sortedResults |
        Format-List

    $suitableCertificates = @(
        $results |
        Where-Object {
            $_.Suitable -eq $true
        }
    )

    if ($suitableCertificates.Count -gt 0) {
        Write-Pass "$($suitableCertificates.Count) suitable WinRM HTTPS certificate(s) found."
    }
    else {
        Write-Fail 'No certificate satisfies every WinRM HTTPS requirement.'

        Write-Host ''
        Write-Host 'Requirement failures by certificate:' -ForegroundColor Yellow

        foreach ($result in $results) {
            Write-Host ''
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
                Write-Host "  - SAN or subject CN does not match $Fqdn" `
                    -ForegroundColor Red
            }
        }
    }

    return $results
}

function Test-WinRmConfiguration {
    Write-Section 'WinRM service and listeners'

    try {
        $service = Get-Service `
            -Name WinRM `
            -ErrorAction Stop

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
        $output = @(
            & winrm.exe enumerate winrm/config/listener 2>&1
        )

        $exitCode = $LASTEXITCODE
        $text = $output -join [Environment]::NewLine

        foreach ($line in $output) {
            Write-Host "  $line"
        }

        if ($exitCode -ne 0) {
            Write-Fail "WinRM listener enumeration failed with exit code $exitCode."
        }
        elseif ($text -match '(?im)^\s*Transport\s*=\s*HTTPS\s*$') {
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
                Select-Object `
                    LocalAddress,
                    LocalPort,
                    State,
                    OwningProcess |
                Format-Table -AutoSize
        }
        else {
            Write-Fail 'No process is listening on TCP 5986.'
        }
    }
    catch {
        Write-Fail "Could not inspect TCP 5986: $($_.Exception.Message)"
    }

    try {
        $localTest = Test-NetConnection `
            -ComputerName localhost `
            -Port 5986 `
            -WarningAction SilentlyContinue

        if ($localTest.TcpTestSucceeded) {
            Write-Pass 'Local TCP connection to port 5986 succeeded.'
        }
        else {
            Write-Fail 'Local TCP connection to port 5986 failed.'
        }

        $localTest |
            Select-Object `
                ComputerName,
                RemoteAddress,
                RemotePort,
                InterfaceAlias,
                SourceAddress,
                TcpTestSucceeded |
            Format-List
    }
    catch {
        Write-Fail "Could not run the local TCP 5986 test: $($_.Exception.Message)"
    }
}

function Test-WinRmFirewall {
    Write-Section 'Windows Firewall rules for TCP 5986'

    try {
        $inboundAllowRules = @(
            Get-NetFirewallRule `
                -Enabled True `
                -Direction Inbound `
                -Action Allow `
                -ErrorAction Stop
        )

        $matchingRules = @()

        foreach ($rule in $inboundAllowRules) {
            $portFilters = @(
                $rule |
                Get-NetFirewallPortFilter `
                    -ErrorAction SilentlyContinue
            )

            foreach ($portFilter in $portFilters) {
                $protocol = [string]$portFilter.Protocol
                $localPort = [string]$portFilter.LocalPort

                $protocolMatches =
                    $protocol -eq 'TCP' -or
                    $protocol -eq '6'

                $portMatches =
                    $localPort -eq '5986' -or
                    $localPort -eq 'Any'

                if (-not ($protocolMatches -and $portMatches)) {
                    continue
                }

                $addressFilters = @(
                    $rule |
                    Get-NetFirewallAddressFilter `
                        -ErrorAction SilentlyContinue
                )

                $remoteAddresses = @()

                foreach ($addressFilter in $addressFilters) {
                    if ($null -ne $addressFilter.RemoteAddress) {
                        $remoteAddresses += @($addressFilter.RemoteAddress)
                    }
                }

                $matchingRules += [pscustomobject]@{
                    DisplayName   = $rule.DisplayName
                    Enabled       = $rule.Enabled
                    Profile       = $rule.Profile
                    Protocol      = $protocol
                    LocalPort     = $localPort
                    RemoteAddress = ($remoteAddresses -join ', ')
                }

                break
            }
        }

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

Test-AppliedGpo `
    -GpoName $ExpectedGpoName

Test-AutoEnrollmentPolicy

Test-EnterpriseCaDiscovery

Test-CertificateTemplates `
    -TemplateName $ExpectedTemplateName

Show-EnrollmentEvents `
    -MaximumEvents $EventCount

if (-not [string]::IsNullOrWhiteSpace($fqdn)) {
    $null = Test-MachineCertificates `
        -Fqdn $fqdn
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

Write-Host ''
Write-Host 'The server is not ready for WinRM over HTTPS.' `
    -ForegroundColor Red

Write-Host ''
Write-Host 'Review each [FAIL] result above.' `
    -ForegroundColor Yellow

Write-Host ''
Write-Host 'After correcting certificate template or enrollment issues, run:' `
    -ForegroundColor Yellow

Write-Host ''
Write-Host '  gpupdate.exe /force'
Write-Host '  certutil.exe -pulse'
Write-Host ''
Write-Host 'Then rerun this script.'

exit 1