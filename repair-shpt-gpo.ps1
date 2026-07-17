#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules ActiveDirectory, ADCSAdministration

<#
.SYNOPSIS
    Repairs the SharePoint WinRM certificate template on the Enterprise CA.

.DESCRIPTION
    Idempotently:
      - Locates the custom and Web Server templates
      - Restores required template attributes from Web Server when missing
      - Ensures Server Authentication, DNS subject/SAN, and key settings
      - Grants Authenticated Users Read so the CA can load the template
      - Grants the CA computer account Read
      - Grants the enrollment group Read, Enroll, and Autoenroll
      - Publishes the template and reloads Certificate Services
#>

[CmdletBinding()]
param(
    [string]$TemplateInternalName = 'AnsibleWinRMHTTPS',
    [string]$TemplateDisplayName = 'Ansible WinRM HTTPS',
    [string]$BaseTemplateName = 'WebServer',
    [string]$EnrollmentGroupName = 'WinRM HTTPS SharePoint Servers',
    [int]$MinimumKeySize = 2048,
    [switch]$DoNotCreateEnrollmentGroup
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module ADCSAdministration -ErrorAction Stop

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Get-TemplateEntry {
    param([Parameter(Mandatory)][string]$Name)

    $rootDse = Get-ADRootDSE -ErrorAction Stop
    $containerDn = @(
        'CN=Certificate Templates'
        'CN=Public Key Services'
        'CN=Services'
        $rootDse.ConfigurationNamingContext
    ) -join ','

    $escaped = $Name.Replace('\', '\5c').
        Replace('*', '\2a').
        Replace('(', '\28').
        Replace(')', '\29')

    $object = Get-ADObject `
        -SearchBase $containerDn `
        -SearchScope OneLevel `
        -LDAPFilter "(&(objectClass=pKICertificateTemplate)(|(cn=$escaped)(displayName=$escaped)))" `
        -Properties * `
        -ErrorAction Stop |
        Select-Object -First 1

    if ($null -eq $object) {
        return $null
    }

    return New-Object System.DirectoryServices.DirectoryEntry `
        -ArgumentList "LDAP://$($object.DistinguishedName)"
}

function Set-PropertyFromBaseWhenMissing {
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]$Target,

        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]$Base,

        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    if ($Target.Properties[$PropertyName].Count -gt 0) {
        return
    }

    if ($Base.Properties[$PropertyName].Count -eq 0) {
        Write-Warning "Base template has no '$PropertyName'; nothing copied."
        return
    }

    $Target.Properties[$PropertyName].Clear()

    foreach ($value in $Base.Properties[$PropertyName]) {
        [void]$Target.Properties[$PropertyName].Add($value)
    }

    Write-Host "[FIX] Restored missing attribute '$PropertyName'."
}

function Add-AllowRule {
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectorySecurity]$Security,

        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$Sid,

        [Parameter(Mandatory)]
        [System.DirectoryServices.ActiveDirectoryRights]$Rights,

        [guid]$ObjectType = [guid]::Empty
    )

    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $rule = if ($ObjectType -eq [guid]::Empty) {
        New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
            -ArgumentList @($Sid, $Rights, $allow)
    }
    else {
        New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
            -ArgumentList @($Sid, $Rights, $allow, $ObjectType)
    }

    [void]$Security.AddAccessRule($rule)
}

function ConvertTo-LdapFilterValue {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $builder = New-Object System.Text.StringBuilder

    foreach ($character in $Value.ToCharArray()) {
        switch ([int][char]$character) {
            0  { [void]$builder.Append('\00'); continue }
            40 { [void]$builder.Append('\28'); continue }
            41 { [void]$builder.Append('\29'); continue }
            42 { [void]$builder.Append('\2a'); continue }
            92 { [void]$builder.Append('\5c'); continue }
            default { [void]$builder.Append($character) }
        }
    }

    return $builder.ToString()
}

function Get-EnrollmentGroup {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [switch]$DoNotCreate
    )

    $escaped = ConvertTo-LdapFilterValue -Value $Name

    $matches = @(
        Get-ADGroup `
            -LDAPFilter "(|(cn=$escaped)(name=$escaped)(displayName=$escaped)(sAMAccountName=$escaped))" `
            -SearchBase (Get-ADDomain).DistinguishedName `
            -SearchScope Subtree `
            -Properties SID, DisplayName, SamAccountName `
            -ErrorAction Stop
    )

    if ($matches.Count -eq 1) {
        return $matches[0]
    }

    if ($matches.Count -gt 1) {
        $details = $matches |
            Select-Object Name, SamAccountName, DistinguishedName |
            Format-Table -AutoSize |
            Out-String

        throw @"
Multiple AD groups matched '$Name'. Rerun with -EnrollmentGroupName set to
the exact sAMAccountName.

$details
"@
    }

    if ($DoNotCreate) {
        throw "Enrollment group '$Name' was not found."
    }

    $domain = Get-ADDomain -ErrorAction Stop
    $groupPath = $domain.UsersContainer

    Write-Warning "Enrollment group '$Name' was not found."
    Write-Host "Creating a new Global Security group in '$groupPath'..."

    $newGroup = New-ADGroup `
        -Name $Name `
        -SamAccountName $Name `
        -DisplayName $Name `
        -GroupCategory Security `
        -GroupScope Global `
        -Path $groupPath `
        -PassThru `
        -ErrorAction Stop

    return Get-ADGroup `
        -Identity $newGroup.DistinguishedName `
        -Properties SID, DisplayName, SamAccountName `
        -ErrorAction Stop
}

function Ensure-TemplatePermissions {
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]$Template,

        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$EnrollmentGroupSid,

        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$CaComputerSid
    )

    $authenticatedUsersSid =
        New-Object System.Security.Principal.SecurityIdentifier `
            -ArgumentList 'S-1-5-11'

    $enrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    $security =
        [System.DirectoryServices.ActiveDirectorySecurity]
        $Template.ObjectSecurity

    Add-AllowRule `
        -Security $security `
        -Sid $authenticatedUsersSid `
        -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead)

    Add-AllowRule `
        -Security $security `
        -Sid $CaComputerSid `
        -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead)

    Add-AllowRule `
        -Security $security `
        -Sid $EnrollmentGroupSid `
        -Rights ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead)

    Add-AllowRule `
        -Security $security `
        -Sid $EnrollmentGroupSid `
        -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
        -ObjectType $enrollGuid

    Add-AllowRule `
        -Security $security `
        -Sid $EnrollmentGroupSid `
        -Rights ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) `
        -ObjectType $autoEnrollGuid

    $Template.ObjectSecurity = $security
}

Write-Step 'Locating certificate templates'
$template = Get-TemplateEntry -Name $TemplateInternalName
if ($null -eq $template) {
    $template = Get-TemplateEntry -Name $TemplateDisplayName
}

if ($null -eq $template) {
    throw "Template '$TemplateInternalName' does not exist in Active Directory."
}

$base = Get-TemplateEntry -Name $BaseTemplateName
if ($null -eq $base) {
    throw "Base template '$BaseTemplateName' does not exist."
}

Write-Host "[OK] Template: $($template.distinguishedName)"
Write-Host "[OK] Base:     $($base.distinguishedName)"

Write-Step 'Repairing required template attributes'

$attributesToRestore = @(
    'flags',
    'revision',
    'pKIDefaultKeySpec',
    'pKIKeyUsage',
    'pKIMaxIssuingDepth',
    'pKICriticalExtensions',
    'pKIExpirationPeriod',
    'pKIOverlapPeriod',
    'msPKI-CSPs',
    'msPKI-RA-Application-Policies',
    'msPKI-RA-Policies',
    'msPKI-Template-Schema-Version'
)

foreach ($attribute in $attributesToRestore) {
    Set-PropertyFromBaseWhenMissing `
        -Target $template `
        -Base $base `
        -PropertyName $attribute
}

$template.Properties['displayName'].Value = $TemplateDisplayName
$template.Properties['msPKI-Minimal-Key-Size'].Value = $MinimumKeySize
$template.Properties['pKIDefaultKeySpec'].Value = 1
$template.Properties['msPKI-RA-Signature'].Value = 0

# Supply DNS name in both subject and SAN.
$template.Properties['msPKI-Certificate-Name-Flag'].Value = 0x18000000

$serverAuthOid = '1.3.6.1.5.5.7.3.1'

$template.Properties['pKIExtendedKeyUsage'].Clear()
[void]$template.Properties['pKIExtendedKeyUsage'].Add($serverAuthOid)

$template.Properties['msPKI-Certificate-Application-Policy'].Clear()
[void]$template.Properties['msPKI-Certificate-Application-Policy'].Add(
    $serverAuthOid
)

$currentEnrollmentFlags = 0
if ($template.Properties['msPKI-Enrollment-Flag'].Count -gt 0) {
    $currentEnrollmentFlags =
        [int]$template.Properties['msPKI-Enrollment-Flag'].Value
}
$template.Properties['msPKI-Enrollment-Flag'].Value =
    ($currentEnrollmentFlags -bor 0x20)

$template.CommitChanges()
$template.RefreshCache()

Write-Host '[OK] Template attributes committed.' -ForegroundColor Green

Write-Step 'Repairing template permissions'
$group = Get-EnrollmentGroup `
    -Name $EnrollmentGroupName `
    -DoNotCreate:$DoNotCreateEnrollmentGroup

Write-Host "[OK] Enrollment group: $($group.DistinguishedName)" `
    -ForegroundColor Green

$caComputer = Get-ADComputer `
    -Identity $env:COMPUTERNAME `
    -Properties SID `
    -ErrorAction Stop

Ensure-TemplatePermissions `
    -Template $template `
    -EnrollmentGroupSid $group.SID `
    -CaComputerSid $caComputer.SID

$template.CommitChanges()
Write-Host '[OK] Template ACL repaired.' -ForegroundColor Green

Write-Step 'Publishing and reloading template'
$published = @(
    Get-CATemplate -ErrorAction Stop |
    Where-Object {
        $nameProperty = $_.PSObject.Properties['Name']
        $null -ne $nameProperty -and
        [string]$nameProperty.Value -eq $TemplateInternalName
    }
)

if ($published.Count -eq 0) {
    Add-CATemplate `
        -Name $TemplateInternalName `
        -Force `
        -ErrorAction Stop

    Write-Host '[OK] Template published.' -ForegroundColor Green
}
else {
    Write-Host '[OK] Template already published.' -ForegroundColor Green
}

Restart-Service -Name CertSvc -Force -ErrorAction Stop
Start-Sleep -Seconds 5

Write-Step 'Verification'
& certutil.exe -template $TemplateInternalName
$templateExitCode = $LASTEXITCODE

if ($templateExitCode -ne 0) {
    throw "CA still cannot load '$TemplateInternalName'. certutil exit code: $templateExitCode."
}

Write-Host ''
Write-Host 'CA template repair completed successfully.' -ForegroundColor Green
Write-Host 'Restart each SharePoint server, then run the node v4 script.'