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

function Get-RootDseProperty {
    param([Parameter(Mandatory)][string]$PropertyName)

    $entry = New-Object System.DirectoryServices.DirectoryEntry `
        -ArgumentList 'LDAP://RootDSE'

    try {
        $entry.RefreshCache(@($PropertyName))
        $values = $entry.Properties[$PropertyName]

        if ($null -eq $values -or $values.Count -eq 0) {
            return $null
        }

        return [string]$values[0]
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
    $configurationNc =
        Get-RootDseProperty -PropertyName 'configurationNamingContext'

    if ([string]::IsNullOrWhiteSpace($configurationNc)) {
        throw @'
The AD Configuration naming context could not be read. Verify that the server
can locate a domain controller and authenticate to LDAP. Useful checks:
  nltest.exe /dsgetdc:%USERDNSDOMAIN%
  Test-ComputerSecureChannel -Verbose
  Resolve-DnsName _ldap._tcp.dc._msdcs.$env:USERDNSDOMAIN
'@
    }

    $containerDn = @(
        'CN=Enrollment Services'
        'CN=Public Key Services'
        'CN=Services'
        $configurationNc
    ) -join ','

    $root = New-Object System.DirectoryServices.DirectoryEntry `
        -ArgumentList "LDAP://$containerDn"

    $searcher = New-Object System.DirectoryServices.DirectorySearcher `
        -ArgumentList $root

    $searcher.Filter = '(objectClass=pKIEnrollmentService)'
    $searcher.SearchScope =
        [System.DirectoryServices.SearchScope]::OneLevel

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

            $cas += [pscustomobject]@{
                Name = $name
                DnsHostName = $hostName
                Configuration = "$hostName\$name"
                CertificateTemplates = $templates
            }
        }

        return $cas
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

& nltest.exe /dsgetdc:$env:USERDNSDOMAIN
if ($LASTEXITCODE -ne 0) {
    throw "Domain controller discovery failed with exit code $LASTEXITCODE."
}

Write-Step 'Checking Enterprise CA publication'
$cas = @(Get-EnterpriseCas)

if ($cas.Count -eq 0) {
    throw 'No Enterprise CA publication objects were found in Active Directory.'
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

if (-not $templatePublished) {
    throw "Template '$TemplateInternalName' is not published by any discovered Enterprise CA."
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