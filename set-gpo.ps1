#requires -RunAsAdministrator
#requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$GpoName = 'Servers - SQL',

    # Change this if your actual OU hierarchy differs.
    [string]$TargetOuDn,

    [string]$ServiceAccountName = 's1-mssql-ansible',
    [string]$AdminGroupName     = 's1-mssql-ansible-admins',

    # By default, create both objects in the domain's Users container.
    [string]$AccountPath,

    # Restrict WinRM to an Ansible controller IP/CIDR when possible.
    # Examples:
    #   '10.20.30.40'
    #   '10.20.30.0/24'
    # '*' permits all source addresses.
    [string]$WinRmIPv4Filter = '*',

    [securestring]$AccountPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory
Import-Module GroupPolicy

$domain = Get-ADDomain

if (-not $TargetOuDn) {
    $TargetOuDn = "OU=SQL,OU=Servers,$($domain.DistinguishedName)"
}

if (-not $AccountPath) {
    $AccountPath = $domain.UsersContainer
}

if (-not $AccountPassword) {
    $AccountPassword = Read-Host `
        "Enter the password for $($domain.NetBIOSName)\$ServiceAccountName" `
        -AsSecureString
}

function Assert-AdContainer {
    param([Parameter(Mandatory)][string]$DistinguishedName)

    try {
        Get-ADObject -Identity $DistinguishedName -ErrorAction Stop | Out-Null
    }
    catch {
        throw "AD container not found: $DistinguishedName"
    }
}

function Ensure-AdSecurityGroup {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    $group = Get-ADGroup -LDAPFilter "(sAMAccountName=$Name)" `
        -Properties GroupCategory, GroupScope -ErrorAction SilentlyContinue

    if (-not $group) {
        Write-Host "Creating AD security group: $Name"

        New-ADGroup `
            -Name $Name `
            -SamAccountName $Name `
            -DisplayName $Name `
            -Description 'Local administrators on SQL servers for Ansible management' `
            -GroupCategory Security `
            -GroupScope Global `
            -Path $Path

        $group = Get-ADGroup -Identity $Name
    }
    else {
        if ($group.GroupCategory -ne 'Security') {
            throw "An AD group named '$Name' exists but is not a security group."
        }

        Write-Host "AD security group already exists: $Name"
    }

    return $group
}

function Ensure-AdServiceUser {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][securestring]$Password
    )

    $user = Get-ADUser -LDAPFilter "(sAMAccountName=$Name)" `
        -Properties Enabled, PasswordNeverExpires `
        -ErrorAction SilentlyContinue

    if (-not $user) {
        Write-Host "Creating AD service user: $Name"

        New-ADUser `
            -Name $Name `
            -SamAccountName $Name `
            -UserPrincipalName "$Name@$($domain.DNSRoot)" `
            -DisplayName $Name `
            -Description 'Ansible service account for managing SQL servers' `
            -Path $Path `
            -AccountPassword $Password `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -CannotChangePassword $true

        $user = Get-ADUser -Identity $Name -Properties Enabled
    }
    else {
        Write-Host "AD service user already exists: $Name"

        if (-not $user.Enabled) {
            Enable-ADAccount -Identity $user
        }
    }

    return $user
}

function Ensure-GpoLink {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Target
    )

    $inheritance = Get-GPInheritance -Target $Target

    $directLink = $inheritance.GpoLinks |
        Where-Object DisplayName -eq $Name

    if (-not $directLink) {
        Write-Host "Linking GPO '$Name' to '$Target'"
        New-GPLink -Name $Name -Target $Target -LinkEnabled Yes | Out-Null
    }
    elseif (-not $directLink.Enabled) {
        Write-Host "Enabling existing GPO link"
        Set-GPLink -Name $Name -Target $Target -LinkEnabled Yes | Out-Null
    }
    else {
        Write-Host "GPO link already exists and is enabled"
    }
}

function Set-GpoLocalAdministratorsMember {
    param(
        [Parameter(Mandatory)]$Gpo,
        [Parameter(Mandatory)]$DomainGroup
    )

    # Official Local Users and Groups GPP extension identifiers.
    $cseGuid  = '{17D89FEC-5C44-4972-B12D-241CAEF74509}'
    $toolGuid = '{79F92669-4224-476C-9C5C-6EFB4D87DF4A}'
    $extensionPair = "[$cseGuid$toolGuid]"

    $gpoGuidText = "{$($Gpo.Id.ToString().ToUpperInvariant())}"
    $gpoAdPath   = "CN=$gpoGuidText,CN=Policies,CN=System,$($domain.DistinguishedName)"

    $gpoSysvolPath = Join-Path `
        "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies" `
        $gpoGuidText

    $groupsDirectory = Join-Path $gpoSysvolPath `
        'Machine\Preferences\Groups'

    $groupsXmlPath = Join-Path $groupsDirectory 'Groups.xml'
    New-Item -Path $groupsDirectory -ItemType Directory -Force | Out-Null

    if (Test-Path $groupsXmlPath) {
        [xml]$xml = Get-Content -LiteralPath $groupsXmlPath -Raw
    }
    else {
        $xml = New-Object System.Xml.XmlDocument
        $declaration = $xml.CreateXmlDeclaration('1.0', 'utf-8', $null)
        [void]$xml.AppendChild($declaration)

        $root = $xml.CreateElement('Groups')
        $root.SetAttribute(
            'clsid',
            '{3125E937-EB16-4B4C-9934-544FC6D24D26}'
        )
        [void]$xml.AppendChild($root)
    }

    $groupSid     = $DomainGroup.SID.Value
    $domainMember = "$($domain.NetBIOSName)\$($DomainGroup.SamAccountName)"

    # A stable UID makes subsequent executions update the same preference item.
    $preferenceUid = '{A48750E4-81AB-4BB9-ADBA-3FCF528A19AE}'

    $existingItem = $xml.SelectSingleNode(
        "/Groups/Group[@uid='$preferenceUid']"
    )

    if (-not $existingItem) {
        $existingItem = $xml.CreateElement('Group')
        [void]$xml.DocumentElement.AppendChild($existingItem)
    }
    else {
        $existingItem.RemoveAll()
    }

    $existingItem.SetAttribute(
        'clsid',
        '{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}'
    )
    $existingItem.SetAttribute(
        'name',
        'Administrators (built-in)'
    )
    $existingItem.SetAttribute('image', '2')
    $existingItem.SetAttribute(
        'changed',
        (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    )
    $existingItem.SetAttribute('uid', $preferenceUid)
    $existingItem.SetAttribute('userContext', '0')
    $existingItem.SetAttribute('removePolicy', '0')

    $properties = $xml.CreateElement('Properties')
    $properties.SetAttribute('action', 'U')
    $properties.SetAttribute('newName', '')
    $properties.SetAttribute(
        'description',
        'Add Ansible SQL administrators without replacing existing members'
    )
    $properties.SetAttribute('deleteAllUsers', '0')
    $properties.SetAttribute('deleteAllGroups', '0')
    $properties.SetAttribute('removeAccounts', '0')
    $properties.SetAttribute('groupName', 'Administrators')
    [void]$existingItem.AppendChild($properties)

    $members = $xml.CreateElement('Members')
    [void]$properties.AppendChild($members)

    $member = $xml.CreateElement('Member')
    $member.SetAttribute('name', $domainMember)
    $member.SetAttribute('action', 'ADD')
    $member.SetAttribute('sid', $groupSid)
    [void]$members.AppendChild($member)

    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.Encoding = New-Object System.Text.UTF8Encoding($false)

    $writer = [System.Xml.XmlWriter]::Create($groupsXmlPath, $settings)

    try {
        $xml.Save($writer)
    }
    finally {
        $writer.Dispose()
    }

    # Register the Local Users and Groups client-side extension without
    # deleting any extensions already configured on the GPO.
    $gpoAdObject = Get-ADObject `
        -Identity $gpoAdPath `
        -Properties gPCMachineExtensionNames, versionNumber

    $extensionNames = [string]$gpoAdObject.gPCMachineExtensionNames

    if ($extensionNames -notlike "*$cseGuid*") {
        $pairs = @(
            [regex]::Matches(
                $extensionNames,
                '\[[^\]]+\]'
            ) | ForEach-Object Value
        )

        $pairs += $extensionPair
        $extensionNames = ($pairs | Sort-Object -Unique) -join ''

        Set-ADObject `
            -Identity $gpoAdPath `
            -Replace @{
                gPCMachineExtensionNames = $extensionNames
            }
    }

    # Increment the computer half of the GPO version number.
    $currentVersion = [int64]$gpoAdObject.versionNumber
    $newVersion = $currentVersion + 65536

    Set-ADObject `
        -Identity $gpoAdPath `
        -Replace @{ versionNumber = $newVersion }

    $gptIniPath = Join-Path $gpoSysvolPath 'GPT.INI'

    @"
[General]
Version=$newVersion
"@ | Set-Content `
        -LiteralPath $gptIniPath `
        -Encoding ASCII

    Write-Host "Configured '$domainMember' as a local Administrators member"
}

# ---------------------------------------------------------------------------
# Validate environment
# ---------------------------------------------------------------------------

Assert-AdContainer -DistinguishedName $TargetOuDn
Assert-AdContainer -DistinguishedName $AccountPath

$gpo = Get-GPO -Name $GpoName -ErrorAction Stop

Write-Host "Domain:       $($domain.DNSRoot)"
Write-Host "Target OU:    $TargetOuDn"
Write-Host "GPO:          $GpoName"
Write-Host "Account path: $AccountPath"

# ---------------------------------------------------------------------------
# Create/update AD objects
# ---------------------------------------------------------------------------

$adminGroup = Ensure-AdSecurityGroup `
    -Name $AdminGroupName `
    -Path $AccountPath

$serviceUser = Ensure-AdServiceUser `
    -Name $ServiceAccountName `
    -Path $AccountPath `
    -Password $AccountPassword

$alreadyMember = Get-ADGroupMember -Identity $adminGroup |
    Where-Object DistinguishedName -eq $serviceUser.DistinguishedName

if (-not $alreadyMember) {
    Add-ADGroupMember -Identity $adminGroup -Members $serviceUser
    Write-Host "Added '$ServiceAccountName' to '$AdminGroupName'"
}
else {
    Write-Host "'$ServiceAccountName' is already in '$AdminGroupName'"
}

# ---------------------------------------------------------------------------
# Ensure GPO applies to the SQL OU
# ---------------------------------------------------------------------------

Ensure-GpoLink -Name $GpoName -Target $TargetOuDn

# ---------------------------------------------------------------------------
# Enable WinRM through policy
# ---------------------------------------------------------------------------

$winRmPolicyKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'

Set-GPRegistryValue `
    -Name $GpoName `
    -Key $winRmPolicyKey `
    -ValueName 'AllowAutoConfig' `
    -Type DWord `
    -Value 1

Set-GPRegistryValue `
    -Name $GpoName `
    -Key $winRmPolicyKey `
    -ValueName 'IPv4Filter' `
    -Type String `
    -Value $WinRmIPv4Filter

Set-GPRegistryValue `
    -Name $GpoName `
    -Key $winRmPolicyKey `
    -ValueName 'IPv6Filter' `
    -Type String `
    -Value ''

# Keep secure domain authentication enabled.
Set-GPRegistryValue `
    -Name $GpoName `
    -Key $winRmPolicyKey `
    -ValueName 'AllowBasic' `
    -Type DWord `
    -Value 0

Set-GPRegistryValue `
    -Name $GpoName `
    -Key $winRmPolicyKey `
    -ValueName 'AllowUnencryptedTraffic' `
    -Type DWord `
    -Value 0

# Configure the WinRM service for automatic startup.
Set-GPRegistryValue `
    -Name $GpoName `
    -Key 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM' `
    -ValueName 'Start' `
    -Type DWord `
    -Value 2

# Inbound WinRM HTTP firewall policy.
# Restrict RemoteAddresses to the same IPv4 filter where possible.
$remoteAddresses = if ($WinRmIPv4Filter -eq '*') {
    '*'
}
else {
    $WinRmIPv4Filter
}

$firewallRule = @(
    'v2.30'
    'Action=Allow'
    'Active=TRUE'
    'Dir=In'
    'Protocol=6'
    'LPort=5985'
    "RA4=$remoteAddresses"
    'Profile=Domain'
    'Name=Ansible WinRM HTTP'
    'Desc=Allow WinRM HTTP from approved Ansible management addresses'
) -join '|'

$firewallRule += '|'

Set-GPRegistryValue `
    -Name $GpoName `
    -Key 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules' `
    -ValueName 'Ansible-WinRM-HTTP-5985' `
    -Type String `
    -Value $firewallRule

# Add the domain group to local Administrators through GPP.
Set-GpoLocalAdministratorsMember `
    -Gpo $gpo `
    -DomainGroup $adminGroup

Write-Host ''
Write-Host 'Configuration complete.' -ForegroundColor Green
Write-Host "User:  $($domain.NetBIOSName)\$ServiceAccountName"
Write-Host "Group: $($domain.NetBIOSName)\$AdminGroupName"
Write-Host "OU:    $TargetOuDn"
Write-Host "GPO:   $GpoName"