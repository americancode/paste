<#
.SYNOPSIS
    Provisions the SharePoint WinRM HTTPS certificate infrastructure and cleans/configures the SharePoint GPO.

.RUN THIS SCRIPT ON
    The Enterprise CA / domain-management server where the following are available:
      - ActiveDirectory PowerShell module
      - GroupPolicy PowerShell module
      - ADCSAdministration PowerShell module
      - Permission to modify AD certificate templates, publish templates, and edit the SharePoint GPO

.DO NOT RUN ON
    Individual SharePoint nodes.

.WHAT THIS SCRIPT DOES
    - Creates or updates the WinRM HTTPS certificate template.
    - Creates and populates the SharePoint certificate-enrollment security group.
    - Configures certificate auto-enrollment and WinRM service policy in the SharePoint GPO.
    - Removes legacy 5985/5986 firewall registry values previously written into the GPO.
    - Installs a fast startup bootstrap that registers and starts the WinRM HTTPS scheduled task.

.FIREWALL DESIGN
    Firewall is intentionally NOT managed by this GPO. Run Configure-SharePoint-WinRM-Firewall.ps1
    locally on each SharePoint node, or deploy it through your normal software-management system.
#>

#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules ActiveDirectory, GroupPolicy, ADCSAdministration

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$GpoName = 'Servers - SharePoint',
    [string]$TargetOuDn,
    [string]$EnrollmentGroupName = 'WinRM HTTPS SharePoint Servers',
    [string]$EnrollmentGroupSamAccountName = 'WinRM-HTTPS-SP-Servers',
    [string]$EnrollmentGroupOuDn,
    [string]$TemplateDisplayName = 'Ansible WinRM HTTPS',
    [string]$TemplateInternalName = 'AnsibleWinRMHTTPS',
    [string]$BaseTemplateInternalName = 'WebServer',
    [ValidateRange(2048,16384)]
    [int]$MinimumKeySize = 2048,
    [string]$WinRmIPv4Filter = '*',
    [switch]$DoNotAddAllComputersInTargetOu,
    [string[]]$SharePointComputerNames,
    [switch]$EnableGpoLink
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop
Import-Module ADCSAdministration -ErrorAction Stop

$domain = Get-ADDomain -ErrorAction Stop
$rootDse = Get-ADRootDSE -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($TargetOuDn)) {
    $TargetOuDn = "OU=Sharepoint,OU=Servers,$($domain.DistinguishedName)"
}

if ([string]::IsNullOrWhiteSpace($EnrollmentGroupOuDn)) {
    $EnrollmentGroupOuDn = $domain.UsersContainer
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function ConvertTo-LdapFilterValue {
    param([Parameter(Mandatory)][string]$Value)

    $builder = New-Object System.Text.StringBuilder
    foreach ($character in $Value.ToCharArray()) {
        switch ([int][char]$character) {
            0  { [void]$builder.Append('\\00'); continue }
            40 { [void]$builder.Append('\\28'); continue }
            41 { [void]$builder.Append('\\29'); continue }
            42 { [void]$builder.Append('\\2a'); continue }
            92 { [void]$builder.Append('\\5c'); continue }
            default { [void]$builder.Append($character) }
        }
    }
    return $builder.ToString()
}

function Assert-AdObjectExists {
    param([Parameter(Mandatory)][string]$DistinguishedName)

    try {
        Get-ADObject -Identity $DistinguishedName -ErrorAction Stop | Out-Null
    }
    catch {
        throw "AD object not found or inaccessible: $DistinguishedName"
    }
}

function Get-CertificateTemplateContainerDn {
    return "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDse.ConfigurationNamingContext)"
}

function Get-OidContainerDn {
    return "CN=OID,CN=Public Key Services,CN=Services,$($rootDse.ConfigurationNamingContext)"
}

function Get-CertificateTemplateObject {
    param([Parameter(Mandatory)][string]$Name)

    $escaped = ConvertTo-LdapFilterValue -Value $Name
    $matches = @(
        Get-ADObject `
            -SearchBase (Get-CertificateTemplateContainerDn) `
            -SearchScope OneLevel `
            -LDAPFilter "(&(objectClass=pKICertificateTemplate)(|(cn=$escaped)(displayName=$escaped)))" `
            -Properties * `
            -ErrorAction Stop
    )

    if ($matches.Count -gt 1) {
        throw "Multiple certificate templates matched '$Name'."
    }

    if ($matches.Count -eq 1) {
        return $matches[0]
    }

    return $null
}

function New-EnterpriseTemplateOid {
    param([Parameter(Mandatory)][string]$DisplayName)

    $oidContainerDn = Get-OidContainerDn
    $forest = Get-ADForest -ErrorAction Stop
    $forestHash = [math]::Abs($forest.RootDomain.GetHashCode())
    $random = New-Object System.Random

    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $part1 = $random.Next(10000000, 99999999)
        $part2 = $random.Next(10000000, 99999999)
        $part3 = [DateTime]::UtcNow.Ticks.ToString().Substring(8)
        $oid = "1.3.6.1.4.1.311.21.8.$forestHash.$part1.$part2.$part3"
        $cn = ([guid]::NewGuid().Guid).ToUpperInvariant()

        try {
            New-ADObject `
                -Name $cn `
                -Type 'msPKI-Enterprise-Oid' `
                -Path $oidContainerDn `
                -OtherAttributes @{
                    displayName = $DisplayName
                    'msPKI-Cert-Template-OID' = $oid
                    flags = 1
                } `
                -ErrorAction Stop

            return $oid
        }
        catch {
            if ($attempt -eq 20) { throw }
        }
    }
}

function Ensure-CertificateTemplate {
    $template = Get-CertificateTemplateObject -Name $TemplateInternalName
    if ($null -eq $template) {
        $template = Get-CertificateTemplateObject -Name $TemplateDisplayName
    }

    $base = Get-CertificateTemplateObject -Name $BaseTemplateInternalName
    if ($null -eq $base) {
        throw "Base certificate template '$BaseTemplateInternalName' was not found."
    }

    if ($null -eq $template) {
        Write-Host "Creating certificate template '$TemplateDisplayName' from '$BaseTemplateInternalName'..."

        $templateOid = New-EnterpriseTemplateOid -DisplayName $TemplateDisplayName
        $attributes = @{}
        $copyAttributes = @(
            'flags','revision','pKIDefaultKeySpec','pKIKeyUsage',
            'pKIMaxIssuingDepth','pKICriticalExtensions','pKIExpirationPeriod',
            'pKIOverlapPeriod','msPKI-CSPs','msPKI-RA-Application-Policies',
            'msPKI-RA-Policies','msPKI-Template-Schema-Version',
            'msPKI-Template-Minor-Revision','msPKI-Private-Key-Flag',
            'msPKI-Enrollment-Flag','msPKI-Certificate-Name-Flag',
            'msPKI-Minimal-Key-Size','pKIExtendedKeyUsage',
            'msPKI-Certificate-Application-Policy','msPKI-RA-Signature'
        )

        foreach ($attribute in $copyAttributes) {
            $property = $base.PSObject.Properties[$attribute]
            if ($null -ne $property -and $null -ne $property.Value) {
                $attributes[$attribute] = $property.Value
            }
        }

        $attributes['displayName'] = $TemplateDisplayName
        $attributes['msPKI-Cert-Template-OID'] = $templateOid

        New-ADObject `
            -Name $TemplateInternalName `
            -Type 'pKICertificateTemplate' `
            -Path (Get-CertificateTemplateContainerDn) `
            -OtherAttributes $attributes `
            -ErrorAction Stop

        $template = Get-CertificateTemplateObject -Name $TemplateInternalName
        if ($null -eq $template) {
            throw "Template creation returned successfully, but '$TemplateInternalName' could not be read back from AD."
        }
    }

    $replace = @{
        displayName = $TemplateDisplayName
        'msPKI-Minimal-Key-Size' = $MinimumKeySize
        pKIDefaultKeySpec = 1
        'msPKI-RA-Signature' = 0
        'msPKI-Certificate-Name-Flag' = 0x18000000
        pKIExtendedKeyUsage = '1.3.6.1.5.5.7.3.1'
        'msPKI-Certificate-Application-Policy' = '1.3.6.1.5.5.7.3.1'
    }

    $currentEnrollmentFlag = 0
    if ($null -ne $template.'msPKI-Enrollment-Flag') {
        $currentEnrollmentFlag = [int]$template.'msPKI-Enrollment-Flag'
    }
    $replace['msPKI-Enrollment-Flag'] = ($currentEnrollmentFlag -bor 0x20)

    Set-ADObject -Identity $template.DistinguishedName -Replace $replace -ErrorAction Stop
    return Get-CertificateTemplateObject -Name $TemplateInternalName
}

function Ensure-EnrollmentGroup {
    $escapedSam = ConvertTo-LdapFilterValue -Value $EnrollmentGroupSamAccountName
    $escapedName = ConvertTo-LdapFilterValue -Value $EnrollmentGroupName

    $matches = @(
        Get-ADGroup `
            -LDAPFilter "(|(sAMAccountName=$escapedSam)(cn=$escapedName)(displayName=$escapedName))" `
            -SearchBase $domain.DistinguishedName `
            -SearchScope Subtree `
            -Properties SID,GroupCategory,GroupScope `
            -ErrorAction Stop
    )

    if ($matches.Count -gt 1) {
        throw "Multiple groups match '$EnrollmentGroupName' or '$EnrollmentGroupSamAccountName'."
    }

    if ($matches.Count -eq 0) {
        Write-Host "Creating certificate enrollment group '$EnrollmentGroupName'..."
        New-ADGroup `
            -Name $EnrollmentGroupName `
            -SamAccountName $EnrollmentGroupSamAccountName `
            -DisplayName $EnrollmentGroupName `
            -Description 'SharePoint computer accounts permitted to auto-enroll for the WinRM HTTPS certificate' `
            -GroupCategory Security `
            -GroupScope Global `
            -Path $EnrollmentGroupOuDn `
            -ErrorAction Stop

        $matches = @(
            Get-ADGroup `
                -LDAPFilter "(sAMAccountName=$escapedSam)" `
                -SearchBase $domain.DistinguishedName `
                -SearchScope Subtree `
                -Properties SID,GroupCategory,GroupScope `
                -ErrorAction Stop
        )
    }

    if ($matches.Count -ne 1) {
        throw 'Enrollment group could not be resolved uniquely after creation.'
    }

    if ($matches[0].GroupCategory -ne 'Security') {
        throw "'$($matches[0].DistinguishedName)' is not a security group."
    }

    return $matches[0]
}

function Ensure-SharePointComputerMembership {
    param([Parameter(Mandatory)]$Group)

    $computers = @()
    if ($SharePointComputerNames -and $SharePointComputerNames.Count -gt 0) {
        foreach ($computerName in $SharePointComputerNames) {
            $computers += Get-ADComputer -Identity $computerName -ErrorAction Stop
        }
    }
    elseif (-not $DoNotAddAllComputersInTargetOu) {
        $computers = @(
            Get-ADComputer `
                -Filter * `
                -SearchBase $TargetOuDn `
                -SearchScope Subtree `
                -ErrorAction Stop
        )
    }

    if ($computers.Count -eq 0) {
        Write-Warning 'No SharePoint computer accounts were selected for enrollment-group membership.'
        return
    }

    $memberDns = @(
        Get-ADGroupMember -Identity $Group.DistinguishedName -Recursive:$false -ErrorAction Stop |
        ForEach-Object { $_.DistinguishedName }
    )

    foreach ($computer in $computers) {
        if ($memberDns -notcontains $computer.DistinguishedName) {
            Write-Host "Adding computer '$($computer.Name)' to '$($Group.Name)'..."
            Add-ADGroupMember `
                -Identity $Group.DistinguishedName `
                -Members $computer.DistinguishedName `
                -ErrorAction Stop
        }
    }
}

function Add-AdAllowRule {
    param(
        [Parameter(Mandatory)][System.DirectoryServices.ActiveDirectorySecurity]$Security,
        [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier]$Sid,
        [Parameter(Mandatory)][System.DirectoryServices.ActiveDirectoryRights]$Rights,
        [guid]$ObjectType = [guid]::Empty
    )

    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $rule = if ($ObjectType -eq [guid]::Empty) {
        New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($Sid,$Rights,$allow)
    }
    else {
        New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @($Sid,$Rights,$allow,$ObjectType)
    }
    [void]$Security.AddAccessRule($rule)
}

function Ensure-TemplateAcl {
    param(
        [Parameter(Mandatory)]$Template,
        [Parameter(Mandatory)]$EnrollmentGroup
    )

    $templateEntry = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$($Template.DistinguishedName)"
    $security = [System.DirectoryServices.ActiveDirectorySecurity]$templateEntry.ObjectSecurity

    $authenticatedUsersSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-11'
    $enrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    Add-AdAllowRule -Security $security -Sid $authenticatedUsersSid -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead)
    Add-AdAllowRule -Security $security -Sid $EnrollmentGroup.SID -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead)
    Add-AdAllowRule -Security $security -Sid $EnrollmentGroup.SID -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ObjectType $enrollGuid
    Add-AdAllowRule -Security $security -Sid $EnrollmentGroup.SID -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ObjectType $autoEnrollGuid

    $caComputer = Get-ADComputer -Identity $env:COMPUTERNAME -Properties SID -ErrorAction Stop
    Add-AdAllowRule -Security $security -Sid $caComputer.SID -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead)

    $templateEntry.ObjectSecurity = $security
    $templateEntry.CommitChanges()
}

function Ensure-TemplatePublished {
    $publishedNames = @(
        Get-CATemplate -ErrorAction Stop |
        ForEach-Object {
            if ($_.PSObject.Properties['Name']) { [string]$_.Name }
        }
    )

    if ($publishedNames -notcontains $TemplateInternalName) {
        Add-CATemplate -Name $TemplateInternalName -Force -ErrorAction Stop
    }

    Restart-Service -Name CertSvc -Force -ErrorAction Stop
}

function Ensure-Gpo {
    $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if ($null -eq $gpo) {
        $gpo = New-GPO -Name $GpoName -Comment 'SharePoint WinRM HTTPS and certificate auto-enrollment; firewall intentionally managed locally' -ErrorAction Stop
    }

    $inheritance = Get-GPInheritance -Target $TargetOuDn -ErrorAction Stop
    $link = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName } | Select-Object -First 1
    if ($null -eq $link) {
        $linkState = if ($EnableGpoLink) { 'Yes' } else { 'No' }
        New-GPLink -Name $GpoName -Target $TargetOuDn -LinkEnabled $linkState -ErrorAction Stop | Out-Null
    }
    elseif ($EnableGpoLink -and -not $link.Enabled) {
        Set-GPLink -Name $GpoName -Target $TargetOuDn -LinkEnabled Yes -ErrorAction Stop | Out-Null
    }

    return $gpo
}

function Set-GpoRegistrySettings {
    $serviceKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    Set-GPRegistryValue -Name $GpoName -Key $serviceKey -ValueName AllowAutoConfig -Type DWord -Value 1
    Set-GPRegistryValue -Name $GpoName -Key $serviceKey -ValueName IPv4Filter -Type String -Value $WinRmIPv4Filter
    Set-GPRegistryValue -Name $GpoName -Key $serviceKey -ValueName IPv6Filter -Type String -Value ''
    Set-GPRegistryValue -Name $GpoName -Key $serviceKey -ValueName AllowBasic -Type DWord -Value 0
    Set-GPRegistryValue -Name $GpoName -Key $serviceKey -ValueName AllowUnencryptedTraffic -Type DWord -Value 0
    Set-GPRegistryValue -Name $GpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM' -ValueName Start -Type DWord -Value 2
    Set-GPRegistryValue -Name $GpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName AEPolicy -Type DWord -Value 7

    # Remove legacy firewall rules previously written by older versions of this deployment.
    $legacyFirewallKey = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules'
    Remove-GPRegistryValue -Name $GpoName -Key $legacyFirewallKey -ValueName 'Ansible-WinRM-HTTPS-5986' -ErrorAction SilentlyContinue
    Remove-GPRegistryValue -Name $GpoName -Key $legacyFirewallKey -ValueName 'Ansible-WinRM-HTTP-5985' -ErrorAction SilentlyContinue

}

function Set-WinRmHttpsStartupScript {
    param([Parameter(Mandatory)]$Gpo)

    $gpoGuidText = "{$($Gpo.Id.ToString().ToUpperInvariant())}"
    $gpoAdPath = "CN=$gpoGuidText,CN=Policies,CN=System,$($domain.DistinguishedName)"
    $gpoSysvolPath = Join-Path "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies" $gpoGuidText
    $scriptsDirectory = Join-Path $gpoSysvolPath 'Machine\Scripts'
    $startupDirectory = Join-Path $scriptsDirectory 'Startup'
    $startupScriptName = 'Install-WinRmHttpsTask.ps1'
    $startupScriptPath = Join-Path $startupDirectory $startupScriptName
    New-Item -Path $startupDirectory -ItemType Directory -Force | Out-Null

    # This startup script does only fast local work. It never calls gpupdate,
    # waits for certificate enrollment, or modifies WSMan during GP processing.
    $startupScript = @'
# Runs as Local System through computer startup policy.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$root = Join-Path $env:ProgramData 'Ansible-WinRM'
$workerPath = Join-Path $root 'Configure-WinRmHttps.ps1'
$bootstrapLog = Join-Path $root 'Install-WinRmHttpsTask.log'
$taskName = 'Configure Ansible WinRM HTTPS'
New-Item -Path $root -ItemType Directory -Force | Out-Null

function Write-BootstrapLog {
    param([Parameter(Mandatory)][string]$Message)
    Add-Content -LiteralPath $bootstrapLog -Value ('{0:u} {1}' -f (Get-Date),$Message) -Encoding UTF8
}

$worker = @"
Set-StrictMode -Version 2.0
`$ErrorActionPreference = 'Stop'

`$root = Join-Path `$env:ProgramData 'Ansible-WinRM'
`$logPath = Join-Path `$root 'Configure-WinRmHttps.log'
New-Item -Path `$root -ItemType Directory -Force | Out-Null

function Write-SetupLog {
    param([Parameter(Mandatory)][string]`$Message)
    Add-Content -LiteralPath `$logPath -Value ('{0:u} {1}' -f (Get-Date),`$Message) -Encoding UTF8
}

function Test-ServerAuthenticationEku {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]`$Certificate)
    `$eku = `$Certificate.Extensions | Where-Object { `$_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if (`$null -eq `$eku) { return `$false }
    try {
        `$parsed = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension -ArgumentList `$eku,`$eku.Critical
        foreach (`$usage in `$parsed.EnhancedKeyUsages) {
            if ([string]`$usage.Value -eq '1.3.6.1.5.5.7.3.1') { return `$true }
        }
    }
    catch {
        try {
            `$text = `$eku.Format(`$false)
            if (`$text -match '1\.3\.6\.1\.5\.5\.7\.3\.1' -or `$text -match 'Server Authentication') { return `$true }
        }
        catch { }
    }
    return `$false
}

function Get-CertificateDnsNames {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]`$Certificate)
    `$names = @()
    try {
        foreach (`$item in @(`$Certificate.DnsNameList)) {
            if (`$null -ne `$item -and `$item.PSObject.Properties['Unicode']) { `$names += [string]`$item.Unicode }
        }
    }
    catch { }
    return @(`$names | ForEach-Object { `$_.TrimEnd('.').ToLowerInvariant() } | Select-Object -Unique)
}

function Find-WinRmCertificate {
    param([Parameter(Mandatory)][string]`$Fqdn)
    `$now = Get-Date
    return Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            if (-not `$_.HasPrivateKey -or `$_.NotBefore -gt `$now -or `$_.NotAfter -le `$now) { return `$false }
            if (-not (Test-ServerAuthenticationEku -Certificate `$_)) { return `$false }
            `$dnsNames = @(Get-CertificateDnsNames -Certificate `$_)
            `$subjectCn = ''
            if (`$_.Subject -match '(?:^|,\s*)CN=([^,]+)') { `$subjectCn = `$Matches[1].TrimEnd('.').ToLowerInvariant() }
            return ((`$dnsNames -contains `$Fqdn) -or (`$subjectCn -eq `$Fqdn))
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
}

try {
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM

    `$cs = Get-CimInstance Win32_ComputerSystem
    if (-not `$cs.PartOfDomain) { throw 'Computer is not domain joined.' }
    `$fqdn = ('{0}.{1}' -f `$cs.DNSHostName,`$cs.Domain).TrimEnd('.').ToLowerInvariant()

    # Never run gpupdate here. This task is started by Group Policy.
    & certutil.exe -pulse | Out-Null

    `$certificate = `$null
    for (`$attempt = 1; `$attempt -le 6 -and `$null -eq `$certificate; `$attempt++) {
        `$certificate = Find-WinRmCertificate -Fqdn `$fqdn
        if (`$null -eq `$certificate) { Start-Sleep -Seconds 20 }
    }

    if (`$null -eq `$certificate) {
        Write-SetupLog "No suitable certificate is available for `$fqdn. The task will retry at the next startup."
        exit 0
    }

    `$thumbprint = `$certificate.Thumbprint.Replace(' ','').ToUpperInvariant()
    Import-Module Microsoft.WSMan.Management -ErrorAction SilentlyContinue
    `$httpsListeners = @(Get-WSManInstance -ResourceURI 'winrm/config/Listener' -Enumerate -ErrorAction SilentlyContinue | Where-Object { [string]`$_.Transport -eq 'HTTPS' })
    `$matching = `$httpsListeners | Where-Object {
        `$thumbProperty = `$_.PSObject.Properties['CertificateThumbprint']
        `$hostProperty = `$_.PSObject.Properties['Hostname']
        `$existingThumbprint = if (`$null -ne `$thumbProperty) {
            ([string]`$thumbProperty.Value).Replace(' ','').ToUpperInvariant()
        }
        else { '' }
        `$existingHostname = if (`$null -ne `$hostProperty) {
            ([string]`$hostProperty.Value).TrimEnd('.').ToLowerInvariant()
        }
        else { '' }
        `$existingThumbprint -eq `$thumbprint -and `$existingHostname -eq `$fqdn
    } | Select-Object -First 1

    if (`$null -eq `$matching) {
        foreach (`$listener in `$httpsListeners) {
            Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Address=[string]`$listener.Address; Transport='HTTPS' } -ErrorAction SilentlyContinue
        }
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Address='*'; Transport='HTTPS' } -ValueSet @{ Hostname=`$fqdn; CertificateThumbprint=`$thumbprint; Enabled=`$true } -ErrorAction Stop | Out-Null
        Restart-Service WinRM -Force
        Write-SetupLog "Configured WinRM HTTPS for `$fqdn using `$thumbprint."
    }
    else {
        Write-SetupLog "Existing WinRM HTTPS listener already uses `$thumbprint."
    }
}
catch {
    Write-SetupLog "ERROR: `$(`$_.Exception.Message)"
    exit 1
}
"@

try {
    Set-Content -LiteralPath $workerPath -Value $worker -Encoding UTF8 -Force

    $action = New-ScheduledTaskAction `
        -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workerPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null

    Start-ScheduledTask -TaskName $taskName
    Write-BootstrapLog 'Scheduled task installed and started asynchronously.'
}
catch {
    Write-BootstrapLog "ERROR: $($_.Exception.Message)"
}

# Always return successfully so startup policy cannot hold the boot sequence.
exit 0
'@

    Set-Content -LiteralPath $startupScriptPath -Value $startupScript -Encoding UTF8
    @"
[Startup]
0CmdLine=$startupScriptName
0Parameters=-NoProfile -NonInteractive -ExecutionPolicy Bypass
"@ | Set-Content -LiteralPath (Join-Path $scriptsDirectory 'psscripts.ini') -Encoding Unicode

    $scriptsCse = '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}'
    $scriptsTool = '{40B6664F-4972-11D1-A7CA-0000F87571E3}'
    $extensionPair = "[$scriptsCse$scriptsTool]"
    $gpoAdObject = Get-ADObject -Identity $gpoAdPath -Server $domain.PDCEmulator -Properties gPCMachineExtensionNames,versionNumber -ErrorAction Stop
    $extensionNames = [string]$gpoAdObject.gPCMachineExtensionNames

    if ($extensionNames -notlike "*$scriptsCse*") {
        $pairs = @([regex]::Matches($extensionNames,'\[[^\]]+\]') | ForEach-Object { $_.Value })
        $pairs += $extensionPair
        $extensionNames = ($pairs | Sort-Object -Unique) -join ''
        Set-ADObject -Identity $gpoAdPath -Server $domain.PDCEmulator -Replace @{ gPCMachineExtensionNames=$extensionNames } -ErrorAction Stop
    }

    $currentVersion = [int64]$gpoAdObject.versionNumber
    $newVersion = $currentVersion + 65536
    Set-ADObject -Identity $gpoAdPath -Server $domain.PDCEmulator -Replace @{ versionNumber=$newVersion } -ErrorAction Stop
    @"
[General]
Version=$newVersion
"@ | Set-Content -LiteralPath (Join-Path $gpoSysvolPath 'GPT.INI') -Encoding ASCII
}

function Test-Deployment {
    param(
        [Parameter(Mandatory)]$Template,
        [Parameter(Mandatory)]$Group,
        [Parameter(Mandatory)]$Gpo
    )

    Write-Step 'Validation'
    $failures = New-Object System.Collections.Generic.List[string]

    if ($Template.Name -ne $TemplateInternalName) { $failures.Add('Template internal name mismatch.') }
    if ($Template.DisplayName -ne $TemplateDisplayName) { $failures.Add('Template display name mismatch.') }

    $published = @(Get-CATemplate | ForEach-Object { if ($_.PSObject.Properties['Name']) { [string]$_.Name } })
    if ($published -notcontains $TemplateInternalName) { $failures.Add('Template is not published on the CA.') }

    $members = @(Get-ADGroupMember -Identity $Group.DistinguishedName -Recursive:$false)
    if (-not $DoNotAddAllComputersInTargetOu -and -not $SharePointComputerNames) {
        $expected = @(Get-ADComputer -Filter * -SearchBase $TargetOuDn -SearchScope Subtree)
        foreach ($computer in $expected) {
            if ($members.DistinguishedName -notcontains $computer.DistinguishedName) {
                $failures.Add("Computer '$($computer.Name)' is not in the enrollment group.")
            }
        }
    }

    $gpoCheck = Get-GPO -Guid $Gpo.Id -ErrorAction SilentlyContinue
    if ($null -eq $gpoCheck) { $failures.Add('GPO could not be read back.') }



    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) { Write-Host "[FAIL] $failure" -ForegroundColor Red }
        throw "Deployment validation failed with $($failures.Count) issue(s)."
    }

    Write-Host '[PASS] Template, publication, enrollment group, membership, and GPO validated. Firewall policy is intentionally unmanaged by this GPO.' -ForegroundColor Green
}

Write-Step 'Preflight'
Assert-AdObjectExists -DistinguishedName $TargetOuDn
Assert-AdObjectExists -DistinguishedName $EnrollmentGroupOuDn

$certSvc = Get-Service -Name CertSvc -ErrorAction Stop
Write-Host "CA server: $env:COMPUTERNAME"
Write-Host "CertSvc:   $($certSvc.Status)"
Write-Host "Target OU: $TargetOuDn"

Write-Step 'Enrollment security group and SharePoint computers'
$enrollmentGroup = Ensure-EnrollmentGroup
Ensure-SharePointComputerMembership -Group $enrollmentGroup

Write-Step 'Certificate template'
$template = Ensure-CertificateTemplate
Ensure-TemplateAcl -Template $template -EnrollmentGroup $enrollmentGroup
Ensure-TemplatePublished
$template = Get-CertificateTemplateObject -Name $TemplateInternalName

Write-Step 'Group Policy'
$gpo = Ensure-Gpo
Set-GpoRegistrySettings
Set-WinRmHttpsStartupScript -Gpo $gpo

Test-Deployment -Template $template -Group $enrollmentGroup -Gpo $gpo

Write-Host ''
Write-Host 'PKI and SharePoint GPO deployment completed successfully.' -ForegroundColor Green
Write-Host "Template:         $TemplateDisplayName ($TemplateInternalName)"
Write-Host "Enrollment group: $($enrollmentGroup.SamAccountName)"
Write-Host "GPO:              $GpoName"
Write-Host ''
if ($EnableGpoLink) {
    Write-Host 'The GPO link is enabled. Restart one SharePoint node first and verify it boots normally.' -ForegroundColor Yellow
}
else {
    Write-Host 'The GPO link remains disabled. Review the changes, then rerun with -EnableGpoLink.' -ForegroundColor Yellow
}
Write-Host 'Node configuration runs asynchronously through the scheduled task: Configure Ansible WinRM HTTPS'
Write-Host ''