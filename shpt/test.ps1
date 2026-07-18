<#
.SYNOPSIS
    Validates WinRM HTTPS, its certificate binding, and the effective TCP 5986 firewall rule.

.RUN THIS SCRIPT ON
    A SharePoint node, from an elevated Windows PowerShell 5.1 console.

.OPTIONAL REMOTE TEST
    Use -RemoteTestSource only as a label in the report. The actual cross-network TCP test should be
    run from the DC/AWX network with: Test-NetConnection <SharePointFQDN> -Port 5986
#>

#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$FirewallRuleName = 'Ansible WinRM HTTPS 5986'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$failures = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

function Write-Result {
    param([string]$Name,[bool]$Passed,[string]$Detail)
    $status = if ($Passed) { 'PASS' } else { 'FAIL' }
    $color = if ($Passed) { 'Green' } else { 'Red' }
    Write-Host ("[{0}] {1}: {2}" -f $status,$Name,$Detail) -ForegroundColor $color
}

$cs = Get-CimInstance Win32_ComputerSystem
$fqdn = ('{0}.{1}' -f $cs.DNSHostName,$cs.Domain).TrimEnd('.').ToLowerInvariant()
Write-Host "Validating: $fqdn" -ForegroundColor Cyan
Write-Host ''

$service = Get-Service WinRM
$serviceOk = $service.Status -eq 'Running'
Write-Result 'WinRM service' $serviceOk ("Status={0}, StartType={1}" -f $service.Status,$service.StartType)
if (-not $serviceOk) { $failures.Add('WinRM service is not running.') }

Import-Module Microsoft.WSMan.Management -ErrorAction SilentlyContinue
$listeners = @(
    Get-WSManInstance -ResourceURI 'winrm/config/Listener' -Enumerate -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.Transport -eq 'HTTPS' }
)
$listener = $listeners | Select-Object -First 1
$listenerOk = $null -ne $listener
$listenerDetail = if ($listenerOk) { 'Present' } else { 'Missing' }
Write-Result 'HTTPS listener' $listenerOk $listenerDetail
if (-not $listenerOk) { $failures.Add('No WinRM HTTPS listener exists.') }

$thumbprint = ''
$hostname = ''
if ($listenerOk) {
    $thumbProperty = $listener.PSObject.Properties['CertificateThumbprint']
    $hostProperty = $listener.PSObject.Properties['Hostname']
    if ($null -ne $thumbProperty) { $thumbprint = ([string]$thumbProperty.Value).Replace(' ','').ToUpperInvariant() }
    if ($null -ne $hostProperty) { $hostname = ([string]$hostProperty.Value).TrimEnd('.').ToLowerInvariant() }

    $hostOk = $hostname -eq $fqdn
    Write-Result 'Listener hostname' $hostOk $hostname
    if (-not $hostOk) { $failures.Add("Listener hostname '$hostname' does not equal '$fqdn'.") }
}

$certificate = $null
if (-not [string]::IsNullOrWhiteSpace($thumbprint)) {
    $certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.Thumbprint.Replace(' ','').ToUpperInvariant() -eq $thumbprint
    } | Select-Object -First 1
}
$certificateOk = $null -ne $certificate
$certificateDetail = if ($certificateOk) { "$thumbprint; expires $($certificate.NotAfter)" } else { 'Not found in LocalMachine\\My' }
Write-Result 'Bound certificate' $certificateOk $certificateDetail
if (-not $certificateOk) { $failures.Add('The listener-bound certificate is missing.') }

if ($certificateOk) {
    $validNow = $certificate.NotBefore -le (Get-Date) -and $certificate.NotAfter -gt (Get-Date)
    Write-Result 'Certificate validity' $validNow ("NotBefore={0}; NotAfter={1}" -f $certificate.NotBefore,$certificate.NotAfter)
    if (-not $validNow) { $failures.Add('The listener certificate is not currently valid.') }

    $privateKeyOk = $certificate.HasPrivateKey
    Write-Result 'Certificate private key' $privateKeyOk ("HasPrivateKey={0}" -f $certificate.HasPrivateKey)
    if (-not $privateKeyOk) { $failures.Add('The listener certificate has no private key.') }
}

$rules = @(Get-NetFirewallRule -DisplayName $FirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
$rule = $rules | Select-Object -First 1
$ruleOk = $null -ne $rule -and $rule.Enabled -eq 'True' -and $rule.Action -eq 'Allow' -and $rule.Direction -eq 'Inbound'
$ruleDetail = if ($null -ne $rule) { "Enabled=$($rule.Enabled), Action=$($rule.Action), Profile=$($rule.Profile), Source=$($rule.PolicyStoreSource)" } else { 'Missing' }
Write-Result 'Effective firewall rule' $ruleOk $ruleDetail
if (-not $ruleOk) { $failures.Add("Effective firewall rule '$FirewallRuleName' is missing or disabled.") }

if ($null -ne $rule) {
    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    $portOk = $null -ne $portFilter -and [string]$portFilter.Protocol -eq 'TCP' -and [string]$portFilter.LocalPort -eq '5986'
    Write-Result 'Firewall port filter' $portOk ("Protocol={0}, LocalPort={1}" -f $portFilter.Protocol,$portFilter.LocalPort)
    if (-not $portOk) { $failures.Add('Firewall rule does not permit TCP 5986.') }
}

$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
foreach ($profile in $profiles) {
    if ($profile.Enabled -and $profile.AllowLocalFirewallRules -eq $false) {
        $warnings.Add("Profile '$($profile.Name)' disables local firewall-rule merging.")
    }
}

$localTcp = Test-NetConnection -ComputerName localhost -Port 5986 -WarningAction SilentlyContinue
Write-Result 'Local TCP 5986' $localTcp.TcpTestSucceeded ("TcpTestSucceeded={0}" -f $localTcp.TcpTestSucceeded)
if (-not $localTcp.TcpTestSucceeded) { $failures.Add('TCP 5986 is not reachable locally.') }

try {
    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $wsman = Test-WSMan -ComputerName $fqdn -UseSSL -Port 5986 -SessionOption $sessionOption -ErrorAction Stop
    Write-Result 'Local Test-WSMan HTTPS' $true ("ProductVersion={0}" -f $wsman.ProductVersion)
}
catch {
    Write-Result 'Local Test-WSMan HTTPS' $false $_.Exception.Message
    $failures.Add('Local Test-WSMan over HTTPS failed.')
}

Write-Host ''
foreach ($warning in $warnings) { Write-Warning $warning }

if ($failures.Count -gt 0) {
    Write-Host "Validation failed with $($failures.Count) issue(s):" -ForegroundColor Red
    foreach ($failure in $failures) { Write-Host " - $failure" -ForegroundColor Red }
    exit 1
}

Write-Host 'All local WinRM HTTPS checks passed.' -ForegroundColor Green
Write-Host "From the DC or AWX network, now run: Test-NetConnection $fqdn -Port 5986" -ForegroundColor Yellow