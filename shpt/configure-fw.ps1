<#
.SYNOPSIS
    Creates or repairs the local Windows Firewall inbound rule for WinRM HTTPS TCP 5986.

.RUN THIS SCRIPT ON
    Each SharePoint node, from an elevated Windows PowerShell 5.1 console.

.RECOMMENDED USE
    Start with -RemoteAddress Any while proving connectivity, then restrict it to the AWX/controller
    address or management subnet after testing.

.NOTES
    This is intentionally a local rule. The SharePoint GPO must allow local firewall-rule merging.
#>

#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RuleName = 'Ansible WinRM HTTPS 5986',
    [string[]]$RemoteAddress = @('Any'),
    [ValidateSet('Domain','Private','Public','Any')]
    [string]$Profile = 'Domain',
    [switch]$AllowHttp5985
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Ensure-InboundPortRule {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][uint16]$Port,
        [Parameter(Mandatory)][string[]]$RemoteAddresses,
        [Parameter(Mandatory)][string]$FirewallProfile
    )

    $rules = @(Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue)

    if ($rules.Count -gt 1) {
        $rules | Select-Object -Skip 1 | Remove-NetFirewallRule -ErrorAction Stop
        $rules = @($rules | Select-Object -First 1)
    }

    if ($rules.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess($DisplayName, "Create inbound TCP $Port firewall rule")) {
            New-NetFirewallRule `
                -DisplayName $DisplayName `
                -Description "Allow WinRM management traffic on TCP $Port" `
                -Direction Inbound `
                -Action Allow `
                -Enabled True `
                -Profile $FirewallProfile `
                -Protocol TCP `
                -LocalPort $Port `
                -RemoteAddress $RemoteAddresses `
                -PolicyStore PersistentStore `
                -ErrorAction Stop | Out-Null
        }
    }
    else {
        $rule = $rules[0]
        if ($PSCmdlet.ShouldProcess($DisplayName, "Repair inbound TCP $Port firewall rule")) {
            Set-NetFirewallRule `
                -InputObject $rule `
                -Direction Inbound `
                -Action Allow `
                -Enabled True `
                -Profile $FirewallProfile `
                -ErrorAction Stop | Out-Null

            $rule | Set-NetFirewallPortFilter `
                -Protocol TCP `
                -LocalPort $Port `
                -ErrorAction Stop | Out-Null

            $rule | Set-NetFirewallAddressFilter `
                -RemoteAddress $RemoteAddresses `
                -ErrorAction Stop | Out-Null
        }
    }

    $effective = Get-NetFirewallRule -DisplayName $DisplayName -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    if ($null -eq $effective) {
        throw "Rule '$DisplayName' exists locally but is not effective. A domain GPO may be disabling local firewall-rule merging."
    }

    $portFilter = $effective | Get-NetFirewallPortFilter
    [pscustomobject]@{
        DisplayName       = $effective.DisplayName
        Enabled           = $effective.Enabled
        Direction         = $effective.Direction
        Action            = $effective.Action
        Profile           = $effective.Profile
        Protocol          = $portFilter.Protocol
        LocalPort         = $portFilter.LocalPort
        RemoteAddress     = (($effective | Get-NetFirewallAddressFilter).RemoteAddress -join ',')
        PolicyStoreSource = $effective.PolicyStoreSource
        Status            = $effective.PrimaryStatus
    }
}

$profiles = Get-NetFirewallProfile -PolicyStore ActiveStore
$blockedMerge = @($profiles | Where-Object { $_.Enabled -and $_.AllowLocalFirewallRules -eq $false })
if ($blockedMerge.Count -gt 0) {
    Write-Warning ('Local firewall-rule merging is disabled for: {0}. A GPO must allow local rules or create the rules centrally.' -f (($blockedMerge.Name) -join ', '))
}

$results = @()
$results += Ensure-InboundPortRule -DisplayName $RuleName -Port 5986 -RemoteAddresses $RemoteAddress -FirewallProfile $Profile

if ($AllowHttp5985) {
    $results += Ensure-InboundPortRule -DisplayName "$RuleName - HTTP 5985" -Port 5985 -RemoteAddresses $RemoteAddress -FirewallProfile $Profile
}

$results | Format-Table -AutoSize

Write-Host ''
Write-Host 'Firewall configuration completed.' -ForegroundColor Green
Write-Host 'Test remotely with: Test-NetConnection <server-fqdn> -Port 5986'