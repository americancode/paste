#requires -RunAsAdministrator
#requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding()]
param(
    [string]$GpoName = 'Servers - SharePoint',

    # SharePoint server computer OU
    [string]$TargetOuDn,

    # OU where both the AD user and security group will be created
    [string]$ServiceAccountsOuDn,

    [string]$ServiceAccountName = 's1-sharepoint-ansible',
    [string]$AdminGroupName     = 's1-sharepoint-ansible-admins',

    # Replace "*" with the Ansible controller IP or subnet when possible.
    # Examples:
    #   10.20.30.40
    #   10.20.30.0/24
    [string]$WinRmIPv4Filter = '*',

    # Keep HTTP/5985 enabled during migration. Set to $false after HTTPS is verified.
    [bool]$EnableWinRmHttp = $true,

    # Configure machine certificate auto-enrollment policy. The CA template must
    # already be published and grant the target computers Enroll/Autoenroll.
    [bool]$EnableCertificateAutoEnrollment = $true,

    [securestring]$AccountPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory
Import-Module GroupPolicy

$domain = Get-ADDomain

if (-not $TargetOuDn) {
    $TargetOuDn = "OU=Sharepoint,OU=Servers,$($domain.DistinguishedName)"
}

if (-not $ServiceAccountsOuDn) {
    $ServiceAccountsOuDn = "OU=Service Accounts,$($domain.DistinguishedName)"
}

if (-not $AccountPassword) {
    $AccountPassword = Read-Host `
        "Enter password for $($domain.NetBIOSName)\$ServiceAccountName" `
        -AsSecureString
}

function Assert-AdContainer {
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    try {
        Get-ADObject `
            -Identity $DistinguishedName `
            -ErrorAction Stop |
            Out-Null
    }
    catch {
        throw "AD container not found or inaccessible: $DistinguishedName"
    }
}

function Ensure-AdSecurityGroup {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $group = Get-ADGroup `
        -LDAPFilter "(sAMAccountName=$Name)" `
        -Properties GroupCategory, GroupScope `
        -ErrorAction SilentlyContinue

    if (-not $group) {
        Write-Host "Creating security group '$Name' in '$Path'..."

        New-ADGroup `
            -Name $Name `
            -SamAccountName $Name `
            -DisplayName $Name `
            -Description 'Local administrators on SharePoint servers for Ansible management' `
            -GroupCategory Security `
            -GroupScope Global `
            -Path $Path `
            -ErrorAction Stop

        $group = Get-ADGroup `
            -Identity $Name `
            -Properties GroupCategory, GroupScope
    }
    else {
        if ($group.GroupCategory -ne 'Security') {
            throw "An object named '$Name' exists, but it is not a security group."
        }

        Write-Host "Security group already exists: $($group.DistinguishedName)"
    }

    return $group
}

function Ensure-AdServiceUser {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [securestring]$Password
    )

    $user = Get-ADUser `
        -LDAPFilter "(sAMAccountName=$Name)" `
        -Properties Enabled, PasswordNeverExpires `
        -ErrorAction SilentlyContinue

    if (-not $user) {
        Write-Host "Creating service account '$Name' in '$Path'..."

        New-ADUser `
            -Name $Name `
            -SamAccountName $Name `
            -UserPrincipalName "$Name@$($domain.DNSRoot)" `
            -DisplayName $Name `
            -Description 'Ansible service account for managing SharePoint servers' `
            -Path $Path `
            -AccountPassword $Password `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -CannotChangePassword $true `
            -ErrorAction Stop

        $user = Get-ADUser `
            -Identity $Name `
            -Properties Enabled, PasswordNeverExpires
    }
    else {
        Write-Host "Service account already exists: $($user.DistinguishedName)"

        if (-not $user.Enabled) {
            Write-Host "Enabling service account '$Name'..."
            Enable-ADAccount -Identity $user
        }

        if (-not $user.PasswordNeverExpires) {
            Set-ADUser `
                -Identity $user `
                -PasswordNeverExpires $true
        }
    }

    return $user
}

function Ensure-GroupMembership {
    param(
        [Parameter(Mandatory)]
        $Group,

        [Parameter(Mandatory)]
        $User
    )

    $isMember = Get-ADGroupMember `
        -Identity $Group `
        -Recursive:$false |
        Where-Object {
            $_.DistinguishedName -eq $User.DistinguishedName
        }

    if (-not $isMember) {
        Write-Host "Adding '$($User.SamAccountName)' to '$($Group.SamAccountName)'..."

        Add-ADGroupMember `
            -Identity $Group `
            -Members $User `
            -ErrorAction Stop
    }
    else {
        Write-Host "'$($User.SamAccountName)' is already a member of '$($Group.SamAccountName)'."
    }
}

function Ensure-GpoLink {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Target
    )

    $inheritance = Get-GPInheritance -Target $Target

    $link = $inheritance.GpoLinks |
        Where-Object {
            $_.DisplayName -eq $Name
        }

    if (-not $link) {
        Write-Host "Linking GPO '$Name' to '$Target'..."

        New-GPLink `
            -Name $Name `
            -Target $Target `
            -LinkEnabled Yes |
            Out-Null
    }
    elseif (-not $link.Enabled) {
        Write-Host "Enabling existing GPO link..."

        Set-GPLink `
            -Name $Name `
            -Target $Target `
            -LinkEnabled Yes |
            Out-Null
    }
    else {
        Write-Host "GPO is already linked and enabled."
    }
}

function Set-WinRmGpoSettings {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$IPv4Filter
    )

    Write-Host "Configuring WinRM policy settings..."

    $winRmServicePolicyKey =
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'

    Set-GPRegistryValue `
        -Name $Name `
        -Key $winRmServicePolicyKey `
        -ValueName 'AllowAutoConfig' `
        -Type DWord `
        -Value 1

    Set-GPRegistryValue `
        -Name $Name `
        -Key $winRmServicePolicyKey `
        -ValueName 'IPv4Filter' `
        -Type String `
        -Value $IPv4Filter

    Set-GPRegistryValue `
        -Name $Name `
        -Key $winRmServicePolicyKey `
        -ValueName 'IPv6Filter' `
        -Type String `
        -Value ''

    Set-GPRegistryValue `
        -Name $Name `
        -Key $winRmServicePolicyKey `
        -ValueName 'AllowBasic' `
        -Type DWord `
        -Value 0

    Set-GPRegistryValue `
        -Name $Name `
        -Key $winRmServicePolicyKey `
        -ValueName 'AllowUnencryptedTraffic' `
        -Type DWord `
        -Value 0

    Set-GPRegistryValue `
        -Name $Name `
        -Key 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM' `
        -ValueName 'Start' `
        -Type DWord `
        -Value 2
}

function Set-CertificateAutoEnrollmentGpoSettings {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    Write-Host "Configuring computer certificate auto-enrollment policy..."

    # AEPolicy bitmask:
    # 1 = enroll certificates automatically
    # 2 = renew expired certificates/update pending certificates/remove revoked
    # 4 = update certificates that use certificate templates
    Set-GPRegistryValue `
        -Name $Name `
        -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' `
        -ValueName 'AEPolicy' `
        -Type DWord `
        -Value 7
}

function Set-WinRmFirewallGpoRules {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$RemoteAddresses,

        [Parameter(Mandatory)]
        [bool]$EnableHttp
    )

    Write-Host "Configuring WinRM firewall rules..."

    $addresses = if ($RemoteAddresses -eq '*') {
        '*'
    }
    else {
        $RemoteAddresses
    }

    $firewallPolicyKey =
        'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules'

    $httpsRule = @(
        'v2.30'
        'Action=Allow'
        'Active=TRUE'
        'Dir=In'
        'Protocol=6'
        'LPort=5986'
        "RA4=$addresses"
        'Profile=Domain'
        'Name=Ansible WinRM HTTPS'
        'Desc=Allow WinRM HTTPS from approved Ansible management addresses'
    ) -join '|'

    $httpsRule += '|'

    Set-GPRegistryValue `
        -Name $Name `
        -Key $firewallPolicyKey `
        -ValueName 'Ansible-WinRM-HTTPS-5986' `
        -Type String `
        -Value $httpsRule

    if ($EnableHttp) {
        $httpRule = @(
            'v2.30'
            'Action=Allow'
            'Active=TRUE'
            'Dir=In'
            'Protocol=6'
            'LPort=5985'
            "RA4=$addresses"
            'Profile=Domain'
            'Name=Ansible WinRM HTTP'
            'Desc=Allow WinRM HTTP from approved Ansible management addresses during HTTPS migration'
        ) -join '|'

        $httpRule += '|'

        Set-GPRegistryValue `
            -Name $Name `
            -Key $firewallPolicyKey `
            -ValueName 'Ansible-WinRM-HTTP-5985' `
            -Type String `
            -Value $httpRule
    }
    else {
        Remove-GPRegistryValue `
            -Name $Name `
            -Key $firewallPolicyKey `
            -ValueName 'Ansible-WinRM-HTTP-5985' `
            -ErrorAction SilentlyContinue
    }
}

function Set-GpoWinRmHttpsStartupScript {
    param(
        [Parameter(Mandatory)]
        $Gpo
    )

    Write-Host "Deploying idempotent WinRM HTTPS startup script..."

    $gpoGuidText =
        "{$($Gpo.Id.ToString().ToUpperInvariant())}"

    $gpoAdPath =
        "CN=$gpoGuidText,CN=Policies,CN=System,$($domain.DistinguishedName)"

    $gpoSysvolPath = Join-Path `
        "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies" `
        $gpoGuidText

    $scriptsDirectory = Join-Path `
        $gpoSysvolPath `
        'Machine\Scripts'

    $startupDirectory = Join-Path `
        $scriptsDirectory `
        'Startup'

    $startupScriptName =
        'Configure-WinRmHttps.ps1'

    $startupScriptPath = Join-Path `
        $startupDirectory `
        $startupScriptName

    New-Item `
        -Path $startupDirectory `
        -ItemType Directory `
        -Force |
        Out-Null

    $startupScript = @'
# Runs as Local System through computer startup policy.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$logDirectory = Join-Path $env:ProgramData 'Ansible-WinRM'
$logPath = Join-Path $logDirectory 'Configure-WinRmHttps.log'
New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null

function Write-SetupLog {
    param([Parameter(Mandatory)][string]$Message)

    $line = '{0:u} {1}' -f (Get-Date), $Message
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
}

try {
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $fqdn = [string]$computerSystem.DNSHostName

    if ($computerSystem.PartOfDomain -and $computerSystem.Domain) {
        $fqdn = '{0}.{1}' -f $computerSystem.DNSHostName, $computerSystem.Domain
    }

    $fqdn = $fqdn.TrimEnd('.').ToLowerInvariant()

    if (-not $fqdn) {
        throw 'Unable to determine the computer FQDN.'
    }

    Write-SetupLog "Searching for a Server Authentication certificate for $fqdn."

    $serverAuthenticationOid = '1.3.6.1.5.5.7.3.1'
    $now = Get-Date

    $certificate = Get-ChildItem -Path Cert:\LocalMachine\My |
        Where-Object {
            if (-not $_.HasPrivateKey -or $_.NotAfter -le $now) {
                return $false
            }

            $hasServerAuthentication = @(
                $_.EnhancedKeyUsageList |
                Where-Object { $_.ObjectId.Value -eq $serverAuthenticationOid }
            ).Count -gt 0

            if (-not $hasServerAuthentication) {
                return $false
            }

            $dnsNames = @(
                $_.DnsNameList |
                ForEach-Object { $_.Unicode.TrimEnd('.').ToLowerInvariant() }
            )

            $subjectCn = $null
            if ($_.Subject -match '(?:^|,\s*)CN=([^,]+)') {
                $subjectCn = $Matches[1].TrimEnd('.').ToLowerInvariant()
            }

            ($dnsNames -contains $fqdn) -or ($subjectCn -eq $fqdn)
        } |
        Sort-Object -Property NotAfter -Descending |
        Select-Object -First 1

    if (-not $certificate) {
        Write-SetupLog "No suitable certificate is available. Triggering auto-enrollment and leaving HTTPS unconfigured."
        & certutil.exe -pulse | Out-Null
        exit 0
    }

    $thumbprint = $certificate.Thumbprint.Replace(' ', '').ToUpperInvariant()
    Write-SetupLog "Selected certificate $thumbprint, expiring $($certificate.NotAfter.ToString('u'))."

    $httpsListeners = @(
        Get-WSManInstance `
            -ResourceURI 'winrm/config/Listener' `
            -Enumerate `
            -ErrorAction SilentlyContinue |
        Where-Object { $_.Transport -eq 'HTTPS' }
    )

    $matchingListener = $httpsListeners |
        Where-Object {
            $_.CertificateThumbprint.Replace(' ', '').ToUpperInvariant() -eq $thumbprint -and
            $_.Hostname.TrimEnd('.').ToLowerInvariant() -eq $fqdn
        } |
        Select-Object -First 1

    if ($matchingListener) {
        Write-SetupLog 'The existing HTTPS listener already uses the desired certificate.'
        exit 0
    }

    foreach ($listener in $httpsListeners) {
        Write-SetupLog "Removing stale HTTPS listener using certificate $($listener.CertificateThumbprint)."

        Remove-WSManInstance `
            -ResourceURI 'winrm/config/Listener' `
            -SelectorSet @{
                Address   = [string]$listener.Address
                Transport = 'HTTPS'
            }
    }

    New-WSManInstance `
        -ResourceURI 'winrm/config/Listener' `
        -SelectorSet @{
            Address   = '*'
            Transport = 'HTTPS'
        } `
        -ValueSet @{
            Hostname              = $fqdn
            CertificateThumbprint = $thumbprint
            Enabled               = $true
        } |
        Out-Null

    Restart-Service -Name WinRM -Force
    Write-SetupLog "Created WinRM HTTPS listener for $fqdn on TCP 5986."
}
catch {
    Write-SetupLog "ERROR: $($_.Exception.Message)"
    throw
}
'@

    Set-Content `
        -LiteralPath $startupScriptPath `
        -Value $startupScript `
        -Encoding UTF8

    $powerShellScriptsIniPath = Join-Path `
        $scriptsDirectory `
        'psscripts.ini'

    @"
[Startup]
0CmdLine=$startupScriptName
0Parameters=-NoProfile -NonInteractive -ExecutionPolicy Bypass
"@ | Set-Content `
        -LiteralPath $powerShellScriptsIniPath `
        -Encoding Unicode

    # Computer-side Scripts CSE and Scripts snap-in GUID pair.
    $scriptsCse =
        '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}'

    $scriptsTool =
        '{40B6664F-4972-11D1-A7CA-0000F87571E3}'

    $extensionPair =
        "[$scriptsCse$scriptsTool]"

    $gpoAdObject = Get-ADObject `
        -Identity $gpoAdPath `
        -Properties gPCMachineExtensionNames, versionNumber

    $extensionNames =
        [string]$gpoAdObject.gPCMachineExtensionNames

    if ($extensionNames -notlike "*$scriptsCse*") {
        $pairs = @(
            [regex]::Matches(
                $extensionNames,
                '\[[^\]]+\]'
            ) |
            ForEach-Object {
                $_.Value
            }
        )

        $pairs += $extensionPair

        $extensionNames =
            ($pairs | Sort-Object -Unique) -join ''

        Set-ADObject `
            -Identity $gpoAdPath `
            -Replace @{
                gPCMachineExtensionNames = $extensionNames
            }
    }

    # Increment the computer portion of the GPO version so clients process it.
    $currentVersion =
        [int64]$gpoAdObject.versionNumber

    $newVersion =
        $currentVersion + 65536

    Set-ADObject `
        -Identity $gpoAdPath `
        -Replace @{
            versionNumber = $newVersion
        }

    $gptIniPath = Join-Path `
        $gpoSysvolPath `
        'GPT.INI'

    @"
[General]
Version=$newVersion
"@ | Set-Content `
        -LiteralPath $gptIniPath `
        -Encoding ASCII

    Write-Host "Deployed startup script '$startupScriptName'."
}

function Set-GpoLocalAdministratorsMember {
    param(
        [Parameter(Mandatory)]
        $Gpo,

        [Parameter(Mandatory)]
        $DomainGroup
    )

    Write-Host "Adding domain group to local Administrators through GPP..."

    $localUsersGroupsCse =
        '{17D89FEC-5C44-4972-B12D-241CAEF74509}'

    $localUsersGroupsTool =
        '{79F92669-4224-476C-9C5C-6EFB4D87DF4A}'

    $extensionPair =
        "[$localUsersGroupsCse$localUsersGroupsTool]"

    $gpoGuidText =
        "{$($Gpo.Id.ToString().ToUpperInvariant())}"

    $gpoAdPath =
        "CN=$gpoGuidText,CN=Policies,CN=System,$($domain.DistinguishedName)"

    $gpoSysvolPath = Join-Path `
        "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies" `
        $gpoGuidText

    $groupsDirectory = Join-Path `
        $gpoSysvolPath `
        'Machine\Preferences\Groups'

    $groupsXmlPath = Join-Path `
        $groupsDirectory `
        'Groups.xml'

    New-Item `
        -Path $groupsDirectory `
        -ItemType Directory `
        -Force |
        Out-Null

    if (Test-Path $groupsXmlPath) {
        [xml]$xml = Get-Content `
            -LiteralPath $groupsXmlPath `
            -Raw
    }
    else {
        $xml = New-Object System.Xml.XmlDocument

        $declaration = $xml.CreateXmlDeclaration(
            '1.0',
            'utf-8',
            $null
        )

        [void]$xml.AppendChild($declaration)

        $root = $xml.CreateElement('Groups')

        $root.SetAttribute(
            'clsid',
            '{3125E937-EB16-4B4C-9934-544FC6D24D26}'
        )

        [void]$xml.AppendChild($root)
    }

    $groupSid =
        $DomainGroup.SID.Value

    $domainGroupName =
        "$($domain.NetBIOSName)\$($DomainGroup.SamAccountName)"

    # Stable GUID so rerunning updates the same preference item.
    $preferenceUid =
        '{A48750E4-81AB-4BB9-ADBA-3FCF528A19AE}'

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
        (Get-Date).ToUniversalTime().ToString(
            'yyyy-MM-dd HH:mm:ss'
        )
    )

    $existingItem.SetAttribute(
        'uid',
        $preferenceUid
    )

    $existingItem.SetAttribute(
        'userContext',
        '0'
    )

    $existingItem.SetAttribute(
        'removePolicy',
        '0'
    )

    $properties = $xml.CreateElement('Properties')

    # U = Update, preserving existing local Administrators members.
    $properties.SetAttribute('action', 'U')
    $properties.SetAttribute('newName', '')

    $properties.SetAttribute(
        'description',
        'Add Ansible SharePoint administrators without replacing existing members'
    )

    $properties.SetAttribute(
        'deleteAllUsers',
        '0'
    )

    $properties.SetAttribute(
        'deleteAllGroups',
        '0'
    )

    $properties.SetAttribute(
        'removeAccounts',
        '0'
    )

    $properties.SetAttribute(
        'groupName',
        'Administrators'
    )

    [void]$existingItem.AppendChild($properties)

    $members = $xml.CreateElement('Members')
    [void]$properties.AppendChild($members)

    $member = $xml.CreateElement('Member')

    $member.SetAttribute(
        'name',
        $domainGroupName
    )

    $member.SetAttribute(
        'action',
        'ADD'
    )

    $member.SetAttribute(
        'sid',
        $groupSid
    )

    [void]$members.AppendChild($member)

    $xmlWriterSettings =
        New-Object System.Xml.XmlWriterSettings

    $xmlWriterSettings.Indent = $true

    $xmlWriterSettings.Encoding =
        New-Object System.Text.UTF8Encoding($false)

    $writer = [System.Xml.XmlWriter]::Create(
        $groupsXmlPath,
        $xmlWriterSettings
    )

    try {
        $xml.Save($writer)
    }
    finally {
        $writer.Dispose()
    }

    $gpoAdObject = Get-ADObject `
        -Identity $gpoAdPath `
        -Properties gPCMachineExtensionNames, versionNumber

    $extensionNames =
        [string]$gpoAdObject.gPCMachineExtensionNames

    if ($extensionNames -notlike "*$localUsersGroupsCse*") {
        $pairs = @(
            [regex]::Matches(
                $extensionNames,
                '\[[^\]]+\]'
            ) |
            ForEach-Object {
                $_.Value
            }
        )

        $pairs += $extensionPair

        $extensionNames =
            ($pairs | Sort-Object -Unique) -join ''

        Set-ADObject `
            -Identity $gpoAdPath `
            -Replace @{
                gPCMachineExtensionNames = $extensionNames
            }
    }

    # Increment the computer portion of the GPO version.
    $currentVersion =
        [int64]$gpoAdObject.versionNumber

    $newVersion =
        $currentVersion + 65536

    Set-ADObject `
        -Identity $gpoAdPath `
        -Replace @{
            versionNumber = $newVersion
        }

    $gptIniPath = Join-Path `
        $gpoSysvolPath `
        'GPT.INI'

    @"
[General]
Version=$newVersion
"@ | Set-Content `
        -LiteralPath $gptIniPath `
        -Encoding ASCII

    Write-Host `
        "Configured '$domainGroupName' as a local Administrators member."
}

# -------------------------------------------------------------------------
# Validate AD paths and GPO
# -------------------------------------------------------------------------

Assert-AdContainer `
    -DistinguishedName $TargetOuDn

Assert-AdContainer `
    -DistinguishedName $ServiceAccountsOuDn

$gpo = Get-GPO `
    -Name $GpoName `
    -ErrorAction Stop

Write-Host ''
Write-Host "Domain:             $($domain.DNSRoot)"
Write-Host "SharePoint server OU:      $TargetOuDn"
Write-Host "Service account OU: $ServiceAccountsOuDn"
Write-Host "GPO:                $GpoName"
Write-Host ''

# -------------------------------------------------------------------------
# Create the group and user in the Service Accounts OU
# -------------------------------------------------------------------------

$adminGroup = Ensure-AdSecurityGroup `
    -Name $AdminGroupName `
    -Path $ServiceAccountsOuDn

$serviceUser = Ensure-AdServiceUser `
    -Name $ServiceAccountName `
    -Path $ServiceAccountsOuDn `
    -Password $AccountPassword

Ensure-GroupMembership `
    -Group $adminGroup `
    -User $serviceUser

# -------------------------------------------------------------------------
# Ensure the GPO is linked to the SharePoint server OU
# -------------------------------------------------------------------------

Ensure-GpoLink `
    -Name $GpoName `
    -Target $TargetOuDn

# -------------------------------------------------------------------------
# Configure WinRM and firewall
# -------------------------------------------------------------------------

Set-WinRmGpoSettings `
    -Name $GpoName `
    -IPv4Filter $WinRmIPv4Filter

if ($EnableCertificateAutoEnrollment) {
    Set-CertificateAutoEnrollmentGpoSettings `
        -Name $GpoName
}

Set-WinRmFirewallGpoRules `
    -Name $GpoName `
    -RemoteAddresses $WinRmIPv4Filter `
    -EnableHttp $EnableWinRmHttp

Set-GpoWinRmHttpsStartupScript `
    -Gpo $gpo

# -------------------------------------------------------------------------
# Add the domain group to local Administrators on SharePoint servers
# -------------------------------------------------------------------------

Set-GpoLocalAdministratorsMember `
    -Gpo $gpo `
    -DomainGroup $adminGroup

Write-Host ''
Write-Host 'Configuration complete.' -ForegroundColor Green
Write-Host "Service account: $($domain.NetBIOSName)\$ServiceAccountName"
Write-Host "Security group:  $($domain.NetBIOSName)\$AdminGroupName"
Write-Host "Objects OU:      $ServiceAccountsOuDn"
Write-Host "Servers OU:      $TargetOuDn"
Write-Host "GPO:             $GpoName"
Write-Host "WinRM HTTPS:     Enabled through startup script and TCP 5986 firewall rule"
Write-Host "WinRM HTTP:      $EnableWinRmHttp"
Write-Host "Certificate AE:  $EnableCertificateAutoEnrollment"
Write-Host ''