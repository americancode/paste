#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
    Repairs and configures the SharePoint WinRM GPO.

.DESCRIPTION
    Idempotently configures:
      - WinRM service policy
      - Certificate auto-enrollment
      - Firewall rules for TCP 5986 and optional 5985
      - A computer startup script that triggers enrollment and creates or
        repairs the WinRM HTTPS listener after a suitable certificate exists

    This script does not create or publish the certificate template. Run the
    Enterprise CA configuration script first.
#>

[CmdletBinding()]
param(
    [string]$GpoName = 'Servers - SharePoint',

    [string]$TargetOuDn,

    [string]$WinRmCertificateTemplate = 'AnsibleWinRMHTTPS',

    [string]$WinRmIPv4Filter = '*',

    [bool]$EnableWinRmHttp = $true
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$domain = Get-ADDomain -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($TargetOuDn)) {
    $TargetOuDn = "OU=SharePoint,OU=Servers,$($domain.DistinguishedName)"
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Ensure-Gpo {
    param([Parameter(Mandatory)][string]$Name)

    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $gpo) {
        $gpo = New-GPO `
            -Name $Name `
            -Comment 'SharePoint WinRM, certificate auto-enrollment, and HTTPS listener configuration.' `
            -ErrorAction Stop
        Write-Host "[OK] Created GPO '$Name'." -ForegroundColor Green
    }
    else {
        Write-Host "[OK] Using existing GPO '$Name'." -ForegroundColor Green
    }

    return $gpo
}

function Ensure-GpoLink {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Target
    )

    $inheritance = Get-GPInheritance -Target $Target -ErrorAction Stop
    $existing = @(
        $inheritance.GpoLinks |
        Where-Object {
            $itemName = $null
            if ($null -ne $_.PSObject.Properties['DisplayName']) {
                $itemName = [string]$_.PSObject.Properties['DisplayName'].Value
            }
            elseif ($null -ne $_.PSObject.Properties['Name']) {
                $itemName = [string]$_.PSObject.Properties['Name'].Value
            }

            $itemName -eq $Name
        }
    )

    if ($existing.Count -eq 0) {
        New-GPLink `
            -Name $Name `
            -Target $Target `
            -LinkEnabled Yes `
            -ErrorAction Stop |
            Out-Null
        Write-Host "[OK] Linked GPO to '$Target'." -ForegroundColor Green
    }
    else {
        Set-GPLink `
            -Name $Name `
            -Target $Target `
            -LinkEnabled Yes `
            -ErrorAction Stop |
            Out-Null
        Write-Host '[OK] Existing GPO link is enabled.' -ForegroundColor Green
    }
}

function Set-GpoRegistrySettings {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$IPv4Filter,
        [Parameter(Mandatory)][bool]$EnableHttp
    )

    $winRmServiceKey =
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'

    $settings = @(
        @{ Key = $winRmServiceKey; ValueName = 'AllowAutoConfig'; Type = 'DWord'; Value = 1 }
        @{ Key = $winRmServiceKey; ValueName = 'IPv4Filter'; Type = 'String'; Value = $IPv4Filter }
        @{ Key = $winRmServiceKey; ValueName = 'IPv6Filter'; Type = 'String'; Value = '' }
        @{ Key = $winRmServiceKey; ValueName = 'AllowBasic'; Type = 'DWord'; Value = 0 }
        @{ Key = $winRmServiceKey; ValueName = 'AllowUnencryptedTraffic'; Type = 'DWord'; Value = 0 }
        @{
            Key = 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment'
            ValueName = 'AEPolicy'
            Type = 'DWord'
            Value = 7
        }
        @{
            Key = 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM'
            ValueName = 'Start'
            Type = 'DWord'
            Value = 2
        }
    )

    foreach ($setting in $settings) {
        Set-GPRegistryValue `
            -Name $Name `
            -Key $setting.Key `
            -ValueName $setting.ValueName `
            -Type $setting.Type `
            -Value $setting.Value `
            -ErrorAction Stop
    }

    $firewallKey =
        'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules'

    $httpsRule = @(
        'v2.30'
        'Action=Allow'
        'Active=TRUE'
        'Dir=In'
        'Protocol=6'
        'LPort=5986'
        "RA4=$IPv4Filter"
        'Profile=Domain'
        'Name=Ansible WinRM HTTPS'
        'Desc=Allow WinRM HTTPS from approved management addresses'
    ) -join '|'
    $httpsRule += '|'

    Set-GPRegistryValue `
        -Name $Name `
        -Key $firewallKey `
        -ValueName 'Ansible-WinRM-HTTPS-5986' `
        -Type String `
        -Value $httpsRule `
        -ErrorAction Stop

    if ($EnableHttp) {
        $httpRule = @(
            'v2.30'
            'Action=Allow'
            'Active=TRUE'
            'Dir=In'
            'Protocol=6'
            'LPort=5985'
            "RA4=$IPv4Filter"
            'Profile=Domain'
            'Name=Ansible WinRM HTTP'
            'Desc=Temporary WinRM HTTP access during HTTPS migration'
        ) -join '|'
        $httpRule += '|'

        Set-GPRegistryValue `
            -Name $Name `
            -Key $firewallKey `
            -ValueName 'Ansible-WinRM-HTTP-5985' `
            -Type String `
            -Value $httpRule `
            -ErrorAction Stop
    }
    else {
        Remove-GPRegistryValue `
            -Name $Name `
            -Key $firewallKey `
            -ValueName 'Ansible-WinRM-HTTP-5985' `
            -ErrorAction SilentlyContinue
    }
}

function Install-GpoStartupScript {
    param(
        [Parameter(Mandatory)]$Gpo,
        [Parameter(Mandatory)][string]$TemplateName
    )

    $gpoGuidText = "{$($Gpo.Id.ToString().ToUpperInvariant())}"
    $gpoAdPath =
        "CN=$gpoGuidText,CN=Policies,CN=System,$($domain.DistinguishedName)"

    $gpoSysvolPath = Join-Path `
        "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies" `
        $gpoGuidText

    $scriptsDirectory = Join-Path $gpoSysvolPath 'Machine\Scripts'
    $startupDirectory = Join-Path $scriptsDirectory 'Startup'
    $startupScriptName = 'Repair-SharePoint-WinRmHttps.ps1'
    $startupScriptPath = Join-Path $startupDirectory $startupScriptName

    New-Item -Path $startupDirectory -ItemType Directory -Force | Out-Null

    $startupScript = @'
# Runs as Local System through computer startup policy.
param(
    [string]$TemplateName = '__TEMPLATE_NAME__'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$logDirectory = Join-Path $env:ProgramData 'SharePoint-WinRM'
$logPath = Join-Path $logDirectory 'Repair-WinRmHttps.log'
New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null

function Write-RepairLog {
    param([Parameter(Mandatory)][string]$Message)
    Add-Content `
        -LiteralPath $logPath `
        -Value ('{0:u} {1}' -f (Get-Date), $Message) `
        -Encoding UTF8
}

function Get-ComputerFqdn {
    $computerSystem = Get-CimInstance `
        -ClassName Win32_ComputerSystem `
        -ErrorAction Stop

    if (
        -not $computerSystem.PartOfDomain -or
        [string]::IsNullOrWhiteSpace([string]$computerSystem.Domain)
    ) {
        throw 'This computer is not joined to an Active Directory domain.'
    }

    return ('{0}.{1}' -f
        $computerSystem.DNSHostName,
        $computerSystem.Domain
    ).TrimEnd('.').ToLowerInvariant()
}

function Test-ServerAuthenticationCertificate {
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
    $hasServerAuth = @(
        $Certificate.EnhancedKeyUsageList |
        Where-Object {
            $_.ObjectId.Value -eq $serverAuthOid
        }
    ).Count -gt 0

    if (-not $hasServerAuth) {
        return $false
    }

    $dnsNames = @()
    try {
        $dnsNames = @(
            $Certificate.DnsNameList |
            ForEach-Object {
                if ($null -ne $_.PSObject.Properties['Unicode']) {
                    [string]$_.Unicode
                }
                else {
                    [string]$_
                }
            }
        )
    }
    catch {
        $dnsNames = @()
    }

    foreach ($dnsName in $dnsNames) {
        if (
            -not [string]::IsNullOrWhiteSpace($dnsName) -and
            $dnsName.TrimEnd('.').ToLowerInvariant() -eq $Fqdn
        ) {
            return $true
        }
    }

    $name = $Certificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName,
        $false
    )

    return (
        -not [string]::IsNullOrWhiteSpace($name) -and
        $name.TrimEnd('.').ToLowerInvariant() -eq $Fqdn
    )
}

try {
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM

    $fqdn = Get-ComputerFqdn
    Write-RepairLog "Starting WinRM HTTPS repair for $fqdn."

    & gpupdate.exe /target:computer /force | Out-Null
    & certutil.exe -pulse | Out-Null
    Start-Sleep -Seconds 10

    $certificate = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            Test-ServerAuthenticationCertificate `
                -Certificate $_ `
                -Fqdn $fqdn
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($null -eq $certificate) {
        Write-RepairLog "No suitable certificate found after auto-enrollment pulse. Template expected: $TemplateName."
        exit 0
    }

    $thumbprint =
        $certificate.Thumbprint.Replace(' ', '').ToUpperInvariant()

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
                ([string]$_.CertificateThumbprint).Replace(' ', '').ToUpperInvariant()

            $existingHost =
                ([string]$_.Hostname).TrimEnd('.').ToLowerInvariant()

            $existingThumbprint -eq $thumbprint -and
            $existingHost -eq $fqdn
        }
    ) | Select-Object -First 1

    if ($null -ne $matchingListener) {
        Write-RepairLog "Existing HTTPS listener already uses certificate $thumbprint."
        exit 0
    }

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
    Write-RepairLog "Created HTTPS listener for $fqdn with certificate $thumbprint."
}
catch {
    Write-RepairLog "ERROR: $($_.Exception.Message)"
    throw
}
'@

    $startupScript =
        $startupScript.Replace('__TEMPLATE_NAME__', $TemplateName)

    Set-Content `
        -LiteralPath $startupScriptPath `
        -Value $startupScript `
        -Encoding UTF8

    @"
[Startup]
0CmdLine=powershell.exe
0Parameters=-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$startupScriptName"
"@ | Set-Content `
        -LiteralPath (Join-Path $scriptsDirectory 'psscripts.ini') `
        -Encoding Unicode

    $scriptsCse = '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}'
    $scriptsTool = '{40B6664F-4972-11D1-A7CA-0000F87571E3}'
    $extensionPair = "[$scriptsCse$scriptsTool]"

    $gpoAdObject = Get-ADObject `
        -Identity $gpoAdPath `
        -Properties gPCMachineExtensionNames, versionNumber `
        -ErrorAction Stop

    $extensionNames =
        [string]$gpoAdObject.gPCMachineExtensionNames

    if ($extensionNames -notlike "*$scriptsCse*") {
        $pairs = @(
            [regex]::Matches($extensionNames, '\[[^\]]+\]') |
            ForEach-Object { $_.Value }
        )
        $pairs += $extensionPair

        Set-ADObject `
            -Identity $gpoAdPath `
            -Replace @{
                gPCMachineExtensionNames =
                    (($pairs | Sort-Object -Unique) -join '')
            } `
            -ErrorAction Stop
    }

    $currentVersion = [int64]$gpoAdObject.versionNumber
    $newVersion = $currentVersion + 65536

    Set-ADObject `
        -Identity $gpoAdPath `
        -Replace @{ versionNumber = $newVersion } `
        -ErrorAction Stop

    @"
[General]
Version=$newVersion
"@ | Set-Content `
        -LiteralPath (Join-Path $gpoSysvolPath 'GPT.INI') `
        -Encoding ASCII

    Write-Host "[OK] Installed startup repair script: $startupScriptPath" `
        -ForegroundColor Green
}

Write-Step 'Validating SharePoint OU'
Get-ADOrganizationalUnit `
    -Identity $TargetOuDn `
    -ErrorAction Stop |
    Out-Null
Write-Host "[OK] Target OU: $TargetOuDn" -ForegroundColor Green

Write-Step 'Creating or locating GPO'
$gpo = Ensure-Gpo -Name $GpoName

Write-Step 'Configuring GPO registry and firewall settings'
Set-GpoRegistrySettings `
    -Name $GpoName `
    -IPv4Filter $WinRmIPv4Filter `
    -EnableHttp $EnableWinRmHttp
Write-Host '[OK] WinRM, auto-enrollment, and firewall policy configured.' `
    -ForegroundColor Green

Write-Step 'Installing idempotent startup repair script'
Install-GpoStartupScript `
    -Gpo $gpo `
    -TemplateName $WinRmCertificateTemplate

Write-Step 'Ensuring GPO link'
Ensure-GpoLink `
    -Name $GpoName `
    -Target $TargetOuDn

Write-Host ''
Write-Host 'GPO repair completed.' -ForegroundColor Green
Write-Host "GPO:       $GpoName"
Write-Host "Target OU: $TargetOuDn"
Write-Host ''
Write-Host 'On each SharePoint server, run:' -ForegroundColor Yellow
Write-Host '  gpupdate.exe /force'
Write-Host '  Restart-Computer'