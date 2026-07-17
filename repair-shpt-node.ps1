#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Repairs certificate enrollment and WinRM HTTPS on a SharePoint server.

.DESCRIPTION
    This script:
      - Validates domain connectivity without using ADSI RootDSE
      - Reads the Configuration naming context through LDAP RootDSE safely
      - Enumerates Enterprise CA publication objects
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

function Get-RootDseProperty {
    param(
        [Parameter(Mandatory)]
        [string]$DomainController,

        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    $path = "LDAP://$DomainController/RootDSE"

    $entry = New-Object System.DirectoryServices.DirectoryEntry `
        -ArgumentList @(
            $path,
            $null,
            $null,
            [System.DirectoryServices.AuthenticationTypes]::Secure
        )

    try {
        $entry.RefreshCache(@($PropertyName))
        $values = $entry.Properties[$PropertyName]

        if ($null -eq $values -or $values.Count -eq 0) {
            return $null
        }

        return [string]$values[0]
    }
    catch {
        throw @"
Could not read '$PropertyName' from '$path'.

$($_.Exception.Message)

Verify:
  - The server uses domain DNS servers.
  - TCP/UDP 53 and TCP/UDP 389 are reachable to a domain controller.
  - The computer secure channel is healthy.
  - The current computer account can authenticate to the domain.
"@
    }
    finally {
        $entry.Dispose()
    }
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

function Get-EnterpriseCas {
    param(
        [Parameter(Mandatory)]
        [string]$DomainController
    )

    $configurationNc = Get-RootDseProperty `
        -DomainController $DomainController `
        -PropertyName 'configurationNamingContext'

    if ([string]::IsNullOrWhiteSpace($configurationNc)) {
        throw "The Configuration naming context was empty on '$DomainController'."
    }

    $containerDn = @(
        'CN=Enrollment Services'
        'CN=Public Key Services'
        'CN=Services'
        $configurationNc
    ) -join ','

    $ldapPath = "LDAP://$DomainController/$containerDn"

    $root = New-Object System.DirectoryServices.DirectoryEntry `
        -ArgumentList @(
            $ldapPath,
            $null,
            $null,
            [System.DirectoryServices.AuthenticationTypes]::Secure
        )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher `
        -ArgumentList $root

    $searcher.Filter = '(objectClass=pKIEnrollmentService)'
    $searcher.SearchScope =
        [System.DirectoryServices.SearchScope]::OneLevel
    $searcher.PageSize = 100

    foreach ($property in @(
        'cn',
        'dNSHostName',
        'certificateTemplates'
    )) {
        [void]$searcher.PropertiesToLoad.Add($property)
    }

    try {
        $results = @($searcher.FindAll())
        $cas = @()

        foreach ($result in $results) {
            $name = ''
            if ($result.Properties['cn'].Count -gt 0) {
                $name = [string]$result.Properties['cn'][0]
            }

            $hostName = ''
            if ($result.Properties['dnshostname'].Count -gt 0) {
                $hostName =
                    [string]$result.Properties['dnshostname'][0]
            }

            $templates = @()
            if ($result.Properties['certificatetemplates'].Count -gt 0) {
                $templates = @(
                    $result.Properties['certificatetemplates'] |
                    ForEach-Object { [string]$_ }
                )
            }

            $configuration = ''
            if (
                -not [string]::IsNullOrWhiteSpace($hostName) -and
                -not [string]::IsNullOrWhiteSpace($name)
            ) {
                $configuration = "$hostName\$name"
            }

            $cas += [pscustomobject]@{
                Name = $name
                DnsHostName = $hostName
                Configuration = $configuration
                CertificateTemplates = $templates
            }
        }

        return $cas
    }
    catch {
        throw @"
Failed to search Enterprise CA objects through '$ldapPath'.

$($_.Exception.Message)
"@
    }
    finally {
        $searcher.Dispose()
        $root.Dispose()
    }
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
    if (
        @(
            $Certificate.EnhancedKeyUsageList |
            Where-Object {
                $_.ObjectId.Value -eq $serverAuthOid
            }
        ).Count -eq 0
    ) {
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

Write-Step 'Checking Enterprise CA publication'
$cas = @()

try {
    $cas = @(
        Get-EnterpriseCas `
            -DomainController $domainController
    )
}
catch {
    Write-Warning $_.Exception.Message
    Write-Warning @'
Enterprise CA discovery through LDAP failed. The script will still refresh
Group Policy, trigger certificate auto-enrollment, and attempt WinRM repair.
Review DNS, LDAP, secure-channel, and firewall connectivity if enrollment fails.
'@
}

if ($cas.Count -eq 0) {
    Write-Warning 'No Enterprise CA publication objects were returned to this node.'
}

$templatePublished = $false

foreach ($ca in $cas) {
    Write-Host "CA: $($ca.Configuration)"
    Write-Host "Published templates: $($ca.CertificateTemplates.Count)"

    if (
        $ca.CertificateTemplates -contains $TemplateInternalName -or
        $ca.CertificateTemplates -contains $TemplateDisplayName
    ) {
        $templatePublished = $true
        Write-Host "[OK] Template is published by this CA." `
            -ForegroundColor Green
    }

    if (-not [string]::IsNullOrWhiteSpace($ca.DnsHostName)) {
        Resolve-DnsName `
            -Name $ca.DnsHostName `
            -ErrorAction Stop |
            Select-Object Name, IPAddress |
            Format-Table -AutoSize

        & certutil.exe -config $ca.Configuration -ping
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not contact CA '$($ca.Configuration)'. Check RPC and firewall connectivity."
        }
    }
}

if ($cas.Count -gt 0 -and -not $templatePublished) {
    throw "Template '$TemplateInternalName' is not published by any discovered Enterprise CA."
}
elseif ($cas.Count -eq 0) {
    Write-Warning 'Template publication could not be verified because Enterprise CA discovery failed.'
}

Write-Step 'Refreshing Group Policy and certificate enrollment'
& gpupdate.exe /target:computer /force
if ($LASTEXITCODE -ne 0) {
    throw "gpupdate failed with exit code $LASTEXITCODE."
}

& certutil.exe -pulse
if ($LASTEXITCODE -ne 0) {
    Write-Warning "certutil -pulse returned exit code $LASTEXITCODE."
}

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
No suitable certificate was found in Cert:\LocalMachine\My.

Verify:
  - The computer account is a member of the enrollment security group.
  - The server has restarted since it was added to that group.
  - The template grants Read, Enroll, and Autoenroll.
  - The template includes the computer DNS name and Server Authentication EKU.
  - Certificate enrollment event logs contain no errors.
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