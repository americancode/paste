#requires -Version 5.1
#requires -RunAsAdministrator

# Rebuilt v5 2026-07-17: idempotent controlled template creation and recovery.

<#
.SYNOPSIS
    Configures AD CS certificate auto-enrollment for enabled computers in a
    SharePoint server OU.

.DESCRIPTION
    Finds enabled computers below the target SharePoint OU, synchronizes them
    with an AD security group, configures an existing WinRM HTTPS certificate
    template, publishes it on the local Enterprise CA, and creates/links a
    computer certificate auto-enrollment GPO.

    If the custom template does not exist, the script duplicates the built-in
    Web Server template directly in Active Directory and then applies the
    required WinRM HTTPS settings and permissions.

.NOTES
    Run from an elevated Windows PowerShell 5.1 console on the Enterprise CA
    (or a management server with the required modules and CA access).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ServerOu = 'OU=SharePoint,OU=Servers,DC=compy,DC=local',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TemplateName = 'Ansible WinRM HTTPS',

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$TemplateInternalName = 'AnsibleWinRMHTTPS',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BaseTemplateName = 'WebServer',

    [Parameter()]
    [bool]$CreateTemplateIfMissing = $true,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EnrollmentGroupName = 'WinRM HTTPS SharePoint Servers',

    [Parameter()]
    [ValidateLength(1, 20)]
    [string]$EnrollmentGroupSamAccountName = 'WinRMHTTPS-SP',

    [Parameter()]
    [AllowEmptyString()]
    [string]$EnrollmentGroupPath = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AutoEnrollmentGpoName = 'SharePoint Servers - Certificate Auto-Enrollment',

    [Parameter()]
    [ValidateRange(2048, 16384)]
    [int]$MinimumKeySize = 2048,

    [Parameter()]
    [bool]$RemoveStaleMembers = $true,

    [Parameter()]
    [bool]$RestartCertificateService = $true
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Success {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-InfoMessage {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[INFO] $Message"
}

function Write-WarningMessage {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function ConvertTo-LdapFilterValue {
    <#
        Escapes an LDAP filter value according to RFC 4515.

        This implementation processes one character at a time. It therefore
        avoids the String.Replace(char, char) overload that caused the original
        "newChar" conversion error for the LDAP null escape (\00).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
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

function Get-DomainInformation {
    $domain = Get-ADDomain -ErrorAction Stop

    [pscustomobject]@{
        DistinguishedName = [string]$domain.DistinguishedName
        DnsRoot           = [string]$domain.DNSRoot
        NetBiosName       = [string]$domain.NetBIOSName
    }
}

function Get-OrCreateEnrollmentGroup {
    param(
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$SamAccountName,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName
    $group = Get-ADGroup -LDAPFilter "(sAMAccountName=$escapedSam)" -Properties SID -ErrorAction Stop |
        Select-Object -First 1

    if ($null -ne $group) {
        Write-Success "Using existing group '$($group.Name)'."
        return $group
    }

    Write-InfoMessage "Creating security group '$DisplayName'."

    $group = New-ADGroup `
        -Name $DisplayName `
        -DisplayName $DisplayName `
        -SamAccountName $SamAccountName `
        -GroupCategory Security `
        -GroupScope Global `
        -Path $Path `
        -Description 'SharePoint computers authorized to auto-enroll for WinRM HTTPS certificates.' `
        -PassThru `
        -ErrorAction Stop

    Write-Success "Created group '$($group.DistinguishedName)'."
    Get-ADGroup -Identity $group.DistinguishedName -Properties SID -ErrorAction Stop
}

function Sync-OuComputersToGroup {
    param(
        [Parameter(Mandatory = $true)][string]$SearchBase,
        [Parameter(Mandatory = $true)][object]$Group,
        [Parameter(Mandatory = $true)][bool]$RemoveStale
    )

    $computers = @(
        Get-ADComputer `
            -SearchBase $SearchBase `
            -SearchScope Subtree `
            -Filter { Enabled -eq $true } `
            -Properties Enabled `
            -ErrorAction Stop
    )

    if ($computers.Count -eq 0) {
        throw "No enabled computer accounts were found beneath '$SearchBase'."
    }

    Write-InfoMessage "Found $($computers.Count) enabled computer account(s)."

    $currentComputerMembers = @(
        Get-ADGroupMember `
            -Identity $Group.DistinguishedName `
            -Recursive:$false `
            -ErrorAction Stop |
            Where-Object { $_.ObjectClass -eq 'computer' }
    )

    $currentMemberDns = @($currentComputerMembers | ForEach-Object { $_.DistinguishedName })
    $desiredComputerDns = @($computers | ForEach-Object { $_.DistinguishedName })

    $membersToAdd = @(
        $computers | Where-Object { $_.DistinguishedName -notin $currentMemberDns }
    )

    if ($membersToAdd.Count -gt 0) {
        Add-ADGroupMember `
            -Identity $Group.DistinguishedName `
            -Members $membersToAdd `
            -ErrorAction Stop
        Write-Success "Added $($membersToAdd.Count) computer(s) to the group."
    }
    else {
        Write-Success 'All target computers are already members of the group.'
    }

    if ($RemoveStale) {
        $membersToRemove = @(
            $currentComputerMembers |
                Where-Object { $_.DistinguishedName -notin $desiredComputerDns }
        )

        if ($membersToRemove.Count -gt 0) {
            Remove-ADGroupMember `
                -Identity $Group.DistinguishedName `
                -Members $membersToRemove `
                -Confirm:$false `
                -ErrorAction Stop
            Write-Success "Removed $($membersToRemove.Count) stale computer member(s)."
        }
        else {
            Write-Success 'No stale computer members were found.'
        }
    }

    return $computers
}

function Get-CertificateTemplateContainerDn {
    $rootDse = [ADSI]'LDAP://RootDSE'
    $configurationNc = [string]$rootDse.configurationNamingContext
    return "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configurationNc"
}

function Find-TemplateDirectoryEntry {
    param([Parameter(Mandatory = $true)][string]$Name)

    $containerDn = Get-CertificateTemplateContainerDn
    $searchRoot = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$containerDn"
    $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $searchRoot

    try {
        $escapedName = ConvertTo-LdapFilterValue -Value $Name
        $searcher.Filter = "(&(objectClass=pKICertificateTemplate)(|(cn=$escapedName)(displayName=$escapedName)))"
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
        $result = $searcher.FindOne()

        if ($null -eq $result) {
            return $null
        }

        return $result.GetDirectoryEntry()
    }
    finally {
        $searcher.Dispose()
        $searchRoot.Dispose()
    }
}

function New-UniqueCertificateTemplateOid {
    <#
        Generates a forest-unique certificate-template OID that remains below
        the AD schema limit for msPKI-Cert-Template-OID (64 characters).

        Do not append values to the source template OID: built-in template OIDs
        can already be long enough that appended arcs cause LDAP constraint
        violations during CommitChanges().
    #>
    $containerDn = Get-CertificateTemplateContainerDn

    do {
        # Microsoft enterprise certificate-template OIDs use this namespace.
        # Two positive 31-bit arcs provide ample uniqueness and keep the
        # complete value comfortably below the 64-character schema limit.
        $arc1 = Get-Random -Minimum 100000000 -Maximum 2147483647
        $arc2 = Get-Random -Minimum 100000000 -Maximum 2147483647
        $candidate = "1.3.6.1.4.1.311.21.8.$arc1.$arc2"

        if ($candidate.Length -gt 64) {
            throw "Generated template OID exceeds 64 characters: $candidate"
        }

        $escapedOid = ConvertTo-LdapFilterValue -Value $candidate
        $searchRoot = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$containerDn"
        $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $searchRoot

        try {
            $searcher.Filter = "(&(objectClass=pKICertificateTemplate)(msPKI-Cert-Template-OID=$escapedOid))"
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
            $exists = $null -ne $searcher.FindOne()
        }
        finally {
            $searcher.Dispose()
            $searchRoot.Dispose()
        }
    } while ($exists)

    return $candidate
}

function ConvertTo-AdIntervalBytes {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 3650)]
        [int]$Days
    )

    # AD stores certificate-template durations as a negative 100-nanosecond
    # interval in little-endian signed 64-bit form.
    $ticks = -1L * [int64]$Days * 24L * 60L * 60L * 10000000L
    return [System.BitConverter]::GetBytes($ticks)
}

function Test-CertificateTemplateUsable {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.DirectoryEntry]$Template
    )

    $required = @(
        'cn',
        'displayName',
        'msPKI-Cert-Template-OID',
        'msPKI-Template-Schema-Version',
        'pKIExpirationPeriod',
        'pKIOverlapPeriod'
    )

    foreach ($name in $required) {
        if ($Template.Properties[$name].Count -eq 0) {
            return $false
        }
    }

    return $true
}

function New-CertificateTemplateFromBase {
    param(
        [Parameter(Mandatory = $true)][string]$BaseName,
        [Parameter(Mandatory = $true)][string]$InternalName,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][int]$KeySize
    )

    # First check both identifiers. This makes reruns safe after a successful
    # prior creation or after AD replication exposes the object by either name.
    $existing = Find-TemplateDirectoryEntry -Name $InternalName
    if ($null -eq $existing) {
        $existing = Find-TemplateDirectoryEntry -Name $DisplayName
    }

    if ($null -ne $existing) {
        if (-not (Test-CertificateTemplateUsable -Template $existing)) {
            $dn = [string]$existing.Properties['distinguishedName'].Value
            $existing.Dispose()
            throw "A certificate-template object already exists but is incomplete: '$dn'. Remove or repair that object, then rerun. The script will not delete an existing AD object automatically."
        }

        Write-Success "Using existing certificate template '$DisplayName'."
        return $existing
    }

    # Confirm the requested source exists, but do not bulk-copy every source
    # attribute. Bulk copying operational/system attributes is what caused the
    # LDAP constraint violations in earlier versions.
    $baseTemplate = Find-TemplateDirectoryEntry -Name $BaseName
    if ($null -eq $baseTemplate) {
        throw "Base certificate template '$BaseName' was not found."
    }

    try {
        $schemaVersion = 2
        if ($baseTemplate.Properties['msPKI-Template-Schema-Version'].Count -gt 0) {
            $schemaVersion = [Math]::Max(2, [int]$baseTemplate.Properties['msPKI-Template-Schema-Version'].Value)
        }

        $templateOid = New-UniqueCertificateTemplateOid
        $containerDn = Get-CertificateTemplateContainerDn
        $templateDn = "CN=$InternalName,$containerDn"

        $attributes = @{
            displayName                               = $DisplayName
            flags                                     = 131680
            revision                                  = 100
            pKIDefaultKeySpec                         = 1
            pKIKeyUsage                               = [byte[]](0xA0)
            pKIMaxIssuingDepth                        = 0
            pKICriticalExtensions                     = @('2.5.29.15')
            pKIExpirationPeriod                       = [byte[]](ConvertTo-AdIntervalBytes -Days 730)
            pKIOverlapPeriod                          = [byte[]](ConvertTo-AdIntervalBytes -Days 42)
            pKIExtendedKeyUsage                       = @('1.3.6.1.5.5.7.3.1')
            'msPKI-Cert-Template-OID'                 = $templateOid
            'msPKI-Certificate-Application-Policy'   = @('1.3.6.1.5.5.7.3.1')
            'msPKI-Certificate-Name-Flag'             = 0x18000000
            'msPKI-Enrollment-Flag'                   = 0x20
            'msPKI-Minimal-Key-Size'                  = $KeySize
            'msPKI-Private-Key-Flag'                  = 0
            'msPKI-RA-Signature'                      = 0
            'msPKI-Template-Minor-Revision'           = 0
            'msPKI-Template-Schema-Version'           = $schemaVersion
        }

        Write-InfoMessage "Creating certificate template '$DisplayName' with a controlled attribute set."

        try {
            New-ADObject `
                -Name $InternalName `
                -Type 'pKICertificateTemplate' `
                -Path $containerDn `
                -OtherAttributes $attributes `
                -ErrorAction Stop
        }
        catch {
            # A concurrent run or replication race may have created it after
            # our initial lookup. Re-query before treating the operation as a
            # hard failure.
            $raceWinner = Find-TemplateDirectoryEntry -Name $InternalName
            if ($null -eq $raceWinner) {
                $raceWinner = Find-TemplateDirectoryEntry -Name $DisplayName
            }

            if ($null -ne $raceWinner -and (Test-CertificateTemplateUsable -Template $raceWinner)) {
                Write-WarningMessage 'Another run created the template concurrently; continuing with the existing object.'
                return $raceWinner
            }

            $detail = $_.Exception.Message
            if ($_.Exception.InnerException) {
                $detail = "$detail Inner: $($_.Exception.InnerException.Message)"
            }
            throw "Failed to create certificate template '$DisplayName' at '$templateDn': $detail"
        }

        $created = Find-TemplateDirectoryEntry -Name $InternalName
        if ($null -eq $created) {
            throw "The template create operation returned successfully, but '$templateDn' could not be read back from Active Directory."
        }

        if (-not (Test-CertificateTemplateUsable -Template $created)) {
            $created.Dispose()
            throw "The new template '$templateDn' was created but failed post-create validation."
        }

        Write-Success "Created certificate template '$DisplayName' (internal name '$InternalName')."
        return $created
    }
    finally {
        $baseTemplate.Dispose()
    }
}

function Get-OrCreateTemplateDirectoryEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$InternalName,
        [Parameter(Mandatory = $true)][string]$BaseName,
        [Parameter(Mandatory = $true)][bool]$CreateIfMissing,
        [Parameter(Mandatory = $true)][int]$KeySize
    )

    $template = Find-TemplateDirectoryEntry -Name $Name
    if ($null -ne $template) {
        return $template
    }

    if (-not $CreateIfMissing) {
        throw @"
Certificate template '$Name' was not found in Active Directory.

Create it by opening certtmpl.msc, duplicating the Web Server template, and
setting the display name to '$Name' and template name to '$InternalName'.
Then rerun the script, or rerun with -CreateTemplateIfMissing `$true.
"@
    }

    return New-CertificateTemplateFromBase `
        -BaseName $BaseName `
        -InternalName $InternalName `
        -DisplayName $Name `
        -KeySize $KeySize
}

function Get-LocalEnterpriseCa {
    $configurationPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'

    if (-not (Test-Path -LiteralPath $configurationPath)) {
        throw 'AD CS Certification Authority is not installed on this server.'
    }

    $activeCaName = [string](Get-ItemProperty -LiteralPath $configurationPath -Name Active -ErrorAction Stop).Active
    if ([string]::IsNullOrWhiteSpace($activeCaName)) {
        throw 'The active Certification Authority name could not be determined.'
    }

    $caProperties = Get-ItemProperty -LiteralPath (Join-Path $configurationPath $activeCaName) -ErrorAction Stop
    $caType = [int]$caProperties.CAType

    if ($caType -notin @(0, 1)) {
        throw "The local CA is not an Enterprise CA. Detected CAType: $caType."
    }

    [pscustomobject]@{
        Name          = $activeCaName
        Configuration = "$env:COMPUTERNAME\$activeCaName"
        Type          = $caType
    }
}

function Set-MultiValueDirectoryProperty {
    param(
        [Parameter(Mandatory = $true)][System.DirectoryServices.DirectoryEntry]$Entry,
        [Parameter(Mandatory = $true)][string]$PropertyName,
        [Parameter(Mandatory = $true)][string[]]$Values
    )

    $Entry.Properties[$PropertyName].Clear()
    foreach ($item in $Values) {
        [void]$Entry.Properties[$PropertyName].Add($item)
    }
}

function Set-TemplateEnrollmentPermissions {
    param(
        [Parameter(Mandatory = $true)][System.DirectoryServices.DirectoryEntry]$Template,
        [Parameter(Mandatory = $true)][System.Security.Principal.SecurityIdentifier]$GroupSid
    )

    $enrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $security = [System.DirectoryServices.ActiveDirectorySecurity]$Template.ObjectSecurity

    $existingRules = $security.GetAccessRules(
        $true,
        $false,
        [System.Security.Principal.SecurityIdentifier]
    )

    foreach ($rule in $existingRules) {
        if ($rule.IdentityReference -eq $GroupSid) {
            [void]$security.RemoveAccessRuleSpecific($rule)
        }
    }

    $readRule = New-Object `
        -TypeName System.DirectoryServices.ActiveDirectoryAccessRule `
        -ArgumentList @(
            $GroupSid,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
            $allow
        )

    $enrollRule = New-Object `
        -TypeName System.DirectoryServices.ActiveDirectoryAccessRule `
        -ArgumentList @(
            $GroupSid,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            $allow,
            $enrollGuid
        )

    $autoEnrollRule = New-Object `
        -TypeName System.DirectoryServices.ActiveDirectoryAccessRule `
        -ArgumentList @(
            $GroupSid,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            $allow,
            $autoEnrollGuid
        )

    [void]$security.AddAccessRule($readRule)
    [void]$security.AddAccessRule($enrollRule)
    [void]$security.AddAccessRule($autoEnrollRule)
    $Template.ObjectSecurity = $security
}

function Repair-CertificateTemplate {
    param(
        [Parameter(Mandatory = $true)][System.DirectoryServices.DirectoryEntry]$Template,
        [Parameter(Mandatory = $true)][System.Security.Principal.SecurityIdentifier]$EnrollmentGroupSid,
        [Parameter(Mandatory = $true)][int]$KeySize
    )

    # Include DNS name in SAN and use DNS name as the subject CN.
    $Template.Properties['msPKI-Certificate-Name-Flag'].Value = 0x18000000

    $serverAuthenticationOid = '1.3.6.1.5.5.7.3.1'
    Set-MultiValueDirectoryProperty -Entry $Template -PropertyName 'pKIExtendedKeyUsage' -Values @($serverAuthenticationOid)

    try {
        Set-MultiValueDirectoryProperty `
            -Entry $Template `
            -PropertyName 'msPKI-Certificate-Application-Policy' `
            -Values @($serverAuthenticationOid)
    }
    catch {
        Write-WarningMessage 'Could not update msPKI-Certificate-Application-Policy; pKIExtendedKeyUsage was configured.'
    }

    $currentEnrollmentFlags = 0
    if ($null -ne $Template.Properties['msPKI-Enrollment-Flag'].Value) {
        $currentEnrollmentFlags = [int]$Template.Properties['msPKI-Enrollment-Flag'].Value
    }
    $Template.Properties['msPKI-Enrollment-Flag'].Value = ($currentEnrollmentFlags -bor 0x20)

    $Template.Properties['msPKI-Minimal-Key-Size'].Value = $KeySize
    $Template.Properties['pKIDefaultKeySpec'].Value = 1
    $Template.Properties['msPKI-RA-Signature'].Value = 0

    $currentPrivateKeyFlags = 0
    if ($null -ne $Template.Properties['msPKI-Private-Key-Flag'].Value) {
        $currentPrivateKeyFlags = [int]$Template.Properties['msPKI-Private-Key-Flag'].Value
    }
    $Template.Properties['msPKI-Private-Key-Flag'].Value = ($currentPrivateKeyFlags -band (-bnot 0x10))

    Set-TemplateEnrollmentPermissions -Template $Template -GroupSid $EnrollmentGroupSid
    $Template.CommitChanges()
    $Template.RefreshCache()
}

function Get-PublishedCaTemplate {
    param(
        [Parameter(Mandatory = $true)][string]$InternalName
    )

    return @(
        Get-CATemplate -ErrorAction Stop |
            Where-Object {
                $nameProperty = $_.PSObject.Properties['Name']
                $nameProperty -and ([string]$nameProperty.Value -eq $InternalName)
            }
    ) | Select-Object -First 1
}

function Publish-CertificateTemplate {
    param(
        [Parameter(Mandatory = $true)][string]$InternalName
    )

    $existingTemplate = Get-PublishedCaTemplate -InternalName $InternalName
    if ($null -ne $existingTemplate) {
        Write-Success "Certificate template '$InternalName' is already published on this CA."
        return $existingTemplate
    }

    try {
        Add-CATemplate -Name $InternalName -Force -ErrorAction Stop
    }
    catch {
        # Another invocation or CA refresh may have published it between the
        # initial check and Add-CATemplate. Re-query before treating it as fatal.
        $existingTemplate = Get-PublishedCaTemplate -InternalName $InternalName
        if ($null -ne $existingTemplate) {
            Write-Success "Certificate template '$InternalName' is already published on this CA."
            return $existingTemplate
        }

        throw
    }

    $publishedTemplate = Get-PublishedCaTemplate -InternalName $InternalName
    if ($null -eq $publishedTemplate) {
        throw "Certificate template '$InternalName' was added but could not be verified as published."
    }

    Write-Success "Certificate template '$InternalName' was published on this CA."
    return $publishedTemplate
}

function Configure-AutoEnrollmentGpo {
    param(
        [Parameter(Mandatory = $true)][string]$GpoName,
        [Parameter(Mandatory = $true)][string]$TargetOu
    )

    $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if ($null -eq $gpo) {
        $gpo = New-GPO `
            -Name $GpoName `
            -Comment 'Enables computer certificate auto-enrollment for SharePoint WinRM HTTPS.' `
            -ErrorAction Stop
        Write-Success "Created GPO '$GpoName'."
    }
    else {
        Write-Success "Using existing GPO '$GpoName'."
    }

    $autoEnrollmentRegistryKey = 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment'
    Set-GPRegistryValue `
        -Name $GpoName `
        -Key $autoEnrollmentRegistryKey `
        -ValueName 'AEPolicy' `
        -Type DWord `
        -Value 7 `
        -ErrorAction Stop

    Write-Success 'Configured computer certificate auto-enrollment policy.'

    $inheritance = Get-GPInheritance -Target $TargetOu -ErrorAction Stop
    $existingLink = @($inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName })

    if ($existingLink.Count -eq 0) {
        New-GPLink -Name $GpoName -Target $TargetOu -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Success "Linked GPO to '$TargetOu'."
    }
    else {
        Set-GPLink -Name $GpoName -Target $TargetOu -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Success 'Existing GPO link is enabled.'
    }
}

try {
    Write-Step 'Loading required modules'
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module ADCSAdministration -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
    Write-Success 'Required modules loaded.'

    Write-Step 'Validating SharePoint target OU'
    $targetOu = Get-ADOrganizationalUnit -Identity $ServerOu -ErrorAction Stop
    Write-Success "Target OU found: $($targetOu.DistinguishedName)"

    Write-Step 'Reading domain information'
    $domain = Get-DomainInformation
    if ([string]::IsNullOrWhiteSpace($EnrollmentGroupPath)) {
        $EnrollmentGroupPath = "CN=Users,$($domain.DistinguishedName)"
    }

    $groupContainer = Get-ADObject -Identity $EnrollmentGroupPath -ErrorAction Stop
    Write-Success "Enrollment group container: $($groupContainer.DistinguishedName)"

    Write-Step 'Checking the local Enterprise Certification Authority'
    $ca = Get-LocalEnterpriseCa
    Write-Success "Enterprise CA detected: $($ca.Configuration)"

    Write-Step 'Creating or locating the SharePoint enrollment security group'
    $enrollmentGroup = Get-OrCreateEnrollmentGroup `
        -DisplayName $EnrollmentGroupName `
        -SamAccountName $EnrollmentGroupSamAccountName `
        -Path $EnrollmentGroupPath

    Write-Step 'Synchronizing SharePoint OU computers into the enrollment group'
    $targetComputers = Sync-OuComputersToGroup `
        -SearchBase $ServerOu `
        -Group $enrollmentGroup `
        -RemoveStale $RemoveStaleMembers

    Write-Step "Locating or creating certificate template '$TemplateName'"
    $template = Get-OrCreateTemplateDirectoryEntry `
        -Name $TemplateName `
        -InternalName $TemplateInternalName `
        -BaseName $BaseTemplateName `
        -CreateIfMissing $CreateTemplateIfMissing `
        -KeySize $MinimumKeySize
    $internalTemplateName = [string]$template.Properties['cn'].Value
    $templateDisplayName = [string]$template.Properties['displayName'].Value
    Write-Success "Internal template name: $internalTemplateName"
    Write-Success "Template display name: $templateDisplayName"

    Write-Step 'Repairing certificate template settings and permissions'
    $groupSid = New-Object `
        -TypeName System.Security.Principal.SecurityIdentifier `
        -ArgumentList ([string]$enrollmentGroup.SID.Value)

    Repair-CertificateTemplate `
        -Template $template `
        -EnrollmentGroupSid $groupSid `
        -KeySize $MinimumKeySize
    Write-Success 'Certificate template settings and permissions were updated.'

    Write-Step 'Publishing the certificate template'
    $publishedTemplate = Publish-CertificateTemplate -InternalName $internalTemplateName

    Write-Step 'Configuring certificate auto-enrollment Group Policy'
    Configure-AutoEnrollmentGpo -GpoName $AutoEnrollmentGpoName -TargetOu $ServerOu

    if ($RestartCertificateService) {
        Write-Step 'Restarting the Certification Authority service'
        Restart-Service -Name CertSvc -Force -ErrorAction Stop
        Start-Sleep -Seconds 3

        $certSvc = Get-Service -Name CertSvc -ErrorAction Stop
        if ($certSvc.Status -ne 'Running') {
            throw 'CertSvc did not return to the Running state.'
        }
        Write-Success 'Certification Authority service is running.'
    }

    Write-Step 'Final verification'
    $publishedTemplate = Get-PublishedCaTemplate -InternalName $internalTemplateName

    if ($null -eq $publishedTemplate) {
        throw "The certificate template '$internalTemplateName' could not be verified as published."
    }

    $finalMembers = @(
        Get-ADGroupMember -Identity $enrollmentGroup.DistinguishedName -Recursive:$false -ErrorAction Stop |
            Where-Object { $_.ObjectClass -eq 'computer' } |
            Sort-Object -Property Name
    )

    Write-Host ''
    Write-Host 'Certificate template:' -ForegroundColor White
    $publishedTemplate | Select-Object -Property Name, OID | Format-List

    Write-Host ''
    Write-Host 'Enrollment group:' -ForegroundColor White
    Write-Host "  $($enrollmentGroup.DistinguishedName)"
    Write-Host "  Computer members: $($finalMembers.Count)"
    $finalMembers | Select-Object Name, DistinguishedName | Format-Table -AutoSize

    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor Green
    Write-Host 'SharePoint WinRM HTTPS enrollment configuration completed.' -ForegroundColor Green
    Write-Host ('=' * 60) -ForegroundColor Green

    Write-Host ''
    Write-Host 'Restart the target SharePoint servers, then run:' -ForegroundColor Yellow
    Write-Host '    gpupdate.exe /force'
    Write-Host '    certutil.exe -pulse'

    exit 0
}
catch {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Red
    Write-Host 'CONFIGURATION FAILED' -ForegroundColor Red
    Write-Host ('=' * 78) -ForegroundColor Red
    Write-Host ''
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ''
    Write-Host 'Review the error above. No additional steps were attempted.' -ForegroundColor Yellow
    exit 1
}