#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Repairs certificate enrollment and WinRM HTTPS on a SharePoint server.

.DESCRIPTION
    This script:
      - Validates domain connectivity without using ADSI RootDSE
      - Avoids LDAP RootDSE and DirectoryServices CA discovery
      - Uses native machine certificate enrollment through certreq.exe
      - Triggers computer Group Policy and certificate auto-enrollment
      - Finds a suitable machine certificate
      - Creates or repairs the WinRM HTTPS listener through WSMan cmdlets
      - Ensures an inbound TCP 5986 firewall rule exists

    It is safe to run repeatedly.
#>

[CmdletBinding()]
param(
    [string]$TemplateDisplayName = 'Ansible WinRM HTTPS',
    [string]$TemplateInternalName = 'AnsibleWinRMHTTPS',
    [string]$FirewallRuleName = 'Ansible WinRM HTTPS',
    [int]$EnrollmentWaitSeconds = 20
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Get-DomainControllerName {
    $computerSystem = Get-CimInstance `
        -ClassName Win32_ComputerSystem `
        -ErrorAction Stop

    $domainName = [string]$computerSystem.Domain

    if (
        -not $computerSystem.PartOfDomain -or
        [string]::IsNullOrWhiteSpace($domainName)
    ) {
        throw 'This computer is not joined to an Active Directory domain.'
    }

    $output = @(
        & nltest.exe "/dsgetdc:$domainName" 2>&1
    )
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine

    if ($exitCode -ne 0) {
        throw @"
Domain controller discovery failed for '$domainName'.
nltest exit code: $exitCode

$text
"@
    }

    $match = [regex]::Match(
        $text,
        '(?im)^\s*DC:\s*\\\\([^\s]+)\s*$'
    )

    if (-not $match.Success) {
        throw "nltest succeeded but its domain controller name could not be parsed.`n$text"
    }

    return $match.Groups[1].Value.TrimEnd('.')
}

function Get-ComputerFqdn {
    $computerSystem = Get-CimInstance `
        -ClassName Win32_ComputerSystem `
        -ErrorAction Stop

    if (-not $computerSystem.PartOfDomain) {
        throw 'This computer is not joined to an Active Directory domain.'
    }

    return ('{0}.{1}' -f
        $computerSystem.DNSHostName,
        $computerSystem.Domain
    ).TrimEnd('.').ToLowerInvariant()
}

function Test-TemplateVisibleToClient {
    param(
        [Parameter(Mandatory)]
        [string]$TemplateInternalName,

        [Parameter(Mandatory)]
        [string]$TemplateDisplayName
    )

    $output = @(& certutil.exe -template 2>&1)
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine

    if ($exitCode -ne 0) {
        Write-Warning "certutil -template failed with exit code $exitCode."
        return $false
    }

    return (
        $text -match [regex]::Escape($TemplateInternalName) -or
        $text -match [regex]::Escape($TemplateDisplayName)
    )
}

function Invoke-MachineCertificateEnrollment {
    param(
        [Parameter(Mandatory)]
        [string]$TemplateName
    )

    Write-Host "Requesting machine certificate from template '$TemplateName'..."

    $output = @(
        & certreq.exe `
            -enroll `
            -machine `
            -q `
            $TemplateName 2>&1
    )
    $exitCode = $LASTEXITCODE

    foreach ($line in $output) {
        Write-Host "  $line"
    }

    if ($exitCode -eq 0) {
        Write-Host '[OK] Certificate enrollment request completed.' `
            -ForegroundColor Green
        return $true
    }

    $unsignedExitCode = [uint32]$exitCode
    $hexExitCode = '0x{0:X8}' -f $unsignedExitCode

    Write-Warning "certreq enrollment failed: $exitCode ($hexExitCode)."

    try {
        & certutil.exe -error $hexExitCode
    }
    catch {
    }

    return $false
}

function Test-SuitableCertificate {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory)]
        [string]$Fqdn
    )

    if (-not $Certificate.HasPrivateKey) {
        return $false
    }

    $now = Get-Date
    if (
        $Certificate.NotBefore -gt $now -or
        $Certificate.NotAfter -le $now
    ) {
        return $false
    }

    $serverAuthOid = '1.3.6.1.5.5.7.3.1'
    $hasServerAuthentication = $false

    try {
        foreach ($usage in @($Certificate.EnhancedKeyUsageList)) {
            $oidValue = $null

            $objectIdProperty =
                $usage.PSObject.Properties['ObjectId']

            if ($null -ne $objectIdProperty) {
                $objectId = $objectIdProperty.Value

                if (
                    $null -ne $objectId -and
                    $null -ne $objectId.PSObject.Properties['Value']
                ) {
                    $oidValue =
                        [string]$objectId.PSObject.Properties['Value'].Value
                }
            }

            if (
                [string]::IsNullOrWhiteSpace($oidValue) -and
                $null -ne $usage.PSObject.Properties['Value']
            ) {
                $oidValue =
                    [string]$usage.PSObject.Properties['Value'].Value
            }

            if ($oidValue -eq $serverAuthOid) {
                $hasServerAuthentication = $true
                break
            }
        }
    }
    catch {
        $hasServerAuthentication = $false
    }

    if (-not $hasServerAuthentication) {
        return $false
    }

    try {
        foreach ($name in @($Certificate.DnsNameList)) {
            $text = if ($null -ne $name.PSObject.Properties['Unicode']) {
                [string]$name.Unicode
            }
            else {
                [string]$name
            }

            if (
                $text.TrimEnd('.').ToLowerInvariant() -eq
                $Fqdn
            ) {
                return $true
            }
        }
    }
    catch {
    }

    $dnsName = $Certificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName,
        $false
    )

    return (
        -not [string]::IsNullOrWhiteSpace($dnsName) -and
        $dnsName.TrimEnd('.').ToLowerInvariant() -eq $Fqdn
    )
}

Write-Step 'Checking domain connectivity'
$fqdn = Get-ComputerFqdn
Write-Host "[OK] Computer FQDN: $fqdn" -ForegroundColor Green

$domainController = Get-DomainControllerName
Write-Host "[OK] Discovered domain controller: $domainController" `
    -ForegroundColor Green

try {
    Resolve-DnsName `
        -Name $domainController `
        -ErrorAction Stop |
        Select-Object Name, IPAddress |
        Format-Table -AutoSize
}
catch {
    throw "DNS resolution failed for domain controller '$domainController': $($_.Exception.Message)"
}

$ldapTest = Test-NetConnection `
    -ComputerName $domainController `
    -Port 389 `
    -WarningAction SilentlyContinue

if (-not $ldapTest.TcpTestSucceeded) {
    throw "TCP 389 is not reachable on domain controller '$domainController'."
}

Write-Host '[OK] LDAP TCP 389 is reachable.' -ForegroundColor Green

Write-Step 'Checking certificate enrollment client'
$certreqCommand = Get-Command certreq.exe -ErrorAction SilentlyContinue
$certutilCommand = Get-Command certutil.exe -ErrorAction SilentlyContinue

if ($null -eq $certreqCommand) {
    throw 'certreq.exe is unavailable on this server.'
}

if ($null -eq $certutilCommand) {
    throw 'certutil.exe is unavailable on this server.'
}

Write-Host '[OK] Native certificate enrollment tools are available.' `
    -ForegroundColor Green

Write-Step 'Checking template visibility'
$templateVisible = Test-TemplateVisibleToClient `
    -TemplateInternalName $TemplateInternalName `
    -TemplateDisplayName $TemplateDisplayName

if (-not $templateVisible) {
    throw @"
The certificate enrollment client cannot see template '$TemplateInternalName'.

Do not continue with node enrollment yet. Run the CA-side repair script:
  Repair-SharePoint-WinRM-CertificateTemplate-v8.ps1

Then restart Certificate Services, allow AD replication, restart this server,
and rerun this node script.
"@
}

Write-Host '[OK] Certificate template is visible to this node.' `
    -ForegroundColor Green

Write-Step 'Refreshing Group Policy and certificate enrollment'
& gpupdate.exe /target:computer /force
if ($LASTEXITCODE -ne 0) {
    throw "gpupdate failed with exit code $LASTEXITCODE."
}

& certutil.exe -pulse
if ($LASTEXITCODE -ne 0) {
    Write-Warning "certutil -pulse returned exit code $LASTEXITCODE."
}

$enrollmentSucceeded =
    Invoke-MachineCertificateEnrollment `
        -TemplateName $TemplateInternalName

Start-Sleep -Seconds $EnrollmentWaitSeconds

Write-Step 'Selecting a WinRM HTTPS certificate'
$certificate = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        Test-SuitableCertificate `
            -Certificate $_ `
            -Fqdn $fqdn
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($null -eq $certificate) {
    throw @"
No suitable certificate was found in Cert:\LocalMachine\My after both
auto-enrollment and an explicit certreq machine enrollment attempt.

Verify:
  - The template internal name is '$TemplateInternalName'.
  - The template is published on the issuing Enterprise CA.
  - The computer account has Read, Enroll, and Autoenroll permission.
  - The computer has restarted after enrollment-group membership changed.
  - The template supplies the computer DNS name and Server Authentication EKU.

Run this command separately to see the native enrollment error:
  certreq.exe -enroll -machine $TemplateInternalName
"@
}

$thumbprint =
    $certificate.Thumbprint.Replace(' ', '').ToUpperInvariant()

Write-Host "[OK] Selected certificate: $thumbprint" -ForegroundColor Green
Write-Host "     Subject: $($certificate.Subject)"
Write-Host "     Expires: $($certificate.NotAfter)"

Write-Step 'Creating or repairing the WinRM HTTPS listener'
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

Import-Module Microsoft.WSMan.Management -ErrorAction SilentlyContinue

$httpsListeners = @(
    Get-WSManInstance `
        -ResourceURI 'winrm/config/listener' `
        -Enumerate `
        -ErrorAction SilentlyContinue |
    Where-Object {
        [string]$_.Transport -eq 'HTTPS'
    }
)

$matchingListener = @(
    $httpsListeners |
    Where-Object {
        $existingThumbprint =
            ([string]$_.CertificateThumbprint).
                Replace(' ', '').
                ToUpperInvariant()

        $existingHost =
            ([string]$_.Hostname).
                TrimEnd('.').
                ToLowerInvariant()

        $existingThumbprint -eq $thumbprint -and
        $existingHost -eq $fqdn
    }
) | Select-Object -First 1

if ($null -eq $matchingListener) {
    foreach ($listener in $httpsListeners) {
        Remove-WSManInstance `
            -ResourceURI 'winrm/config/listener' `
            -SelectorSet @{
                Address   = [string]$listener.Address
                Transport = 'HTTPS'
            } `
            -ErrorAction SilentlyContinue
    }

    New-WSManInstance `
        -ResourceURI 'winrm/config/listener' `
        -SelectorSet @{
            Address   = '*'
            Transport = 'HTTPS'
        } `
        -ValueSet @{
            Hostname              = $fqdn
            CertificateThumbprint = $thumbprint
            Enabled               = $true
        } `
        -ErrorAction Stop |
        Out-Null

    Restart-Service -Name WinRM -Force
    Write-Host '[OK] WinRM HTTPS listener created.' -ForegroundColor Green
}
else {
    Write-Host '[OK] Correct WinRM HTTPS listener already exists.' `
        -ForegroundColor Green
}

Write-Step 'Ensuring firewall access on TCP 5986'
$existingFirewallRule = Get-NetFirewallRule `
    -DisplayName $FirewallRuleName `
    -ErrorAction SilentlyContinue

if ($null -eq $existingFirewallRule) {
    New-NetFirewallRule `
        -DisplayName $FirewallRuleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 5986 `
        -Profile Domain `
        -ErrorAction Stop |
        Out-Null
    Write-Host '[OK] Firewall rule created.' -ForegroundColor Green
}
else {
    Set-NetFirewallRule `
        -DisplayName $FirewallRuleName `
        -Enabled True `
        -Direction Inbound `
        -Action Allow `
        -Profile Domain `
        -ErrorAction Stop |
        Out-Null
    Write-Host '[OK] Existing firewall rule enabled.' -ForegroundColor Green
}

Write-Step 'Final verification'
$listeners = @(
    Get-WSManInstance `
        -ResourceURI 'winrm/config/listener' `
        -Enumerate `
        -ErrorAction Stop
)

$listeners |
    Select-Object Address, Transport, Port, Hostname, CertificateThumbprint |
    Format-Table -AutoSize

$tcp = @(
    Get-NetTCPConnection `
        -LocalPort 5986 `
        -State Listen `
        -ErrorAction SilentlyContinue
)

if ($tcp.Count -eq 0) {
    throw 'WinRM HTTPS listener exists, but no process is listening on TCP 5986.'
}

Write-Host '[OK] TCP 5986 is listening.' -ForegroundColor Green

$test = Test-NetConnection `
    -ComputerName localhost `
    -Port 5986 `
    -WarningAction SilentlyContinue

if (-not $test.TcpTestSucceeded) {
    throw 'Local TCP connection to port 5986 failed.'
}

Write-Host '[OK] Local TCP 5986 test succeeded.' -ForegroundColor Green
Write-Host ''
Write-Host 'SharePoint WinRM HTTPS repair completed.' -ForegroundColor Green