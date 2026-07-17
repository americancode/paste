#requires -Version 5.1
#requires -RunAsAdministrator

# Rebuilt v3 2026-07-17: SharePoint edition; creates the custom template when missing.

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
    param([Parameter(Mandatory = $true)][string]$BaseOid)

    $containerDn = Get-CertificateTemplateContainerDn

    do {
        $randomArc1 = Get-Random -Minimum 10000000 -Maximum 2147483647
        $randomArc2 = Get-Random -Minimum 10000000 -Maximum 2147483647
        $candidate = "$BaseOid.$randomArc1.$randomArc2"
        $escapedOid = ConvertTo-LdapFilterValue -Value $candidate

        $searchRoot = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$containerDn"
        $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $searchRoot
        try {
            $searcher.Filter = "(&(objectClass=pKICertificateTemplate)(msPKI-Cert-Template-OID=$escapedOid))"
            $exists = $null -ne $searcher.FindOne()
        }
        finally {
            $searcher.Dispose()
            $searchRoot.Dispose()
        }
    } while ($exists)

    return $candidate
}

function New-CertificateTemplateFromBase {
    param(
        [Parameter(Mandatory = $true)][string]$BaseName,
        [Parameter(Mandatory = $true)][string]$InternalName,
        [Parameter(Mandatory = $true)][string]$DisplayName
    )

    $baseTemplate = Find-TemplateDirectoryEntry -Name $BaseName
    if ($null -eq $baseTemplate) {
        throw "Base certificate template '$BaseName' was not found. Verify the built-in Web Server template exists in certtmpl.msc."
    }

    $existingInternal = Find-TemplateDirectoryEntry -Name $InternalName
    if ($null -ne $existingInternal) {
        return $existingInternal
    }

    $containerDn = Get-CertificateTemplateContainerDn
    $container = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$containerDn"

    # Attributes maintained by AD or unique to the new object are not copied.
    $excludedProperties = @(
        'adspath', 'allowedattributes', 'allowedattributeseffective',
        'allowedchildclasses', 'allowedchildclasseseffective', 'canonicalname',
        'cn', 'createTimeStamp', 'distinguishedName', 'dSCorePropagationData',
        'instanceType', 'isCriticalSystemObject', 'modifyTimeStamp', 'name',
        'nTSecurityDescriptor', 'objectCategory', 'objectClass', 'objectGUID',
        'uSNChanged', 'uSNCreated', 'whenChanged', 'whenCreated',
        'msPKI-Cert-Template-OID', 'displayName'
    )

    $newTemplate = $null

    try {
        Write-InfoMessage "Duplicating certificate template '$BaseName' as '$DisplayName'."
        $newTemplate = $container.Children.Add("CN=$InternalName", 'pKICertificateTemplate')

        foreach ($propertyName in $baseTemplate.Properties.PropertyNames) {
            if ($propertyName -in $excludedProperties) {
                continue
            }

            $values = @($baseTemplate.Properties[$propertyName])
            if ($values.Count -eq 0) {
                continue
            }

            try {
                $newTemplate.Properties[$propertyName].Clear()
                foreach ($value in $values) {
                    [void]$newTemplate.Properties[$propertyName].Add($value)
                }
            }
            catch {
                Write-WarningMessage "Skipped non-copyable template property '$propertyName': $($_.Exception.Message)"
            }
        }

        $baseOid = [string]$baseTemplate.Properties['msPKI-Cert-Template-OID'].Value
        if ([string]::IsNullOrWhiteSpace($baseOid)) {
            throw "Base template '$BaseName' does not contain msPKI-Cert-Template-OID."
        }

        $newTemplate.Properties['displayName'].Value = $DisplayName
        $newTemplate.Properties['msPKI-Cert-Template-OID'].Value = New-UniqueCertificateTemplateOid -BaseOid $baseOid

        # Increment the minor revision to distinguish the duplicate.
        $minorRevision = 0
        if ($null -ne $baseTemplate.Properties['revision'].Value) {
            $minorRevision = [int]$baseTemplate.Properties['revision'].Value
        }
        $newTemplate.Properties['revision'].Value = ($minorRevision + 1)

        $newTemplate.CommitChanges()
        $newTemplate.RefreshCache()
        Write-Success "Created certificate template '$DisplayName' (internal name '$InternalName')."
        return $newTemplate
    }
    catch {
        if ($null -ne $newTemplate) {
            try { $newTemplate.Dispose() } catch { }
        }
        throw "Failed to duplicate certificate template '$BaseName': $($_.Exception.Message)"
    }
    finally {
        $baseTemplate.Dispose()
        $container.Dispose()
    }
}

function Get-OrCreateTemplateDirectoryEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$InternalName,
        [Parameter(Mandatory = $true)][string]$BaseName,
        [Parameter(Mandatory = $true)][bool]$CreateIfMissing
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
        -DisplayName $Name
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

function Publish-CertificateTemplate {
    param(
        [Parameter(Mandatory = $true)][string]$InternalName,
        [Parameter(Mandatory = $true)][string]$DisplayName
    )

    $existingTemplate = Get-CATemplate -ErrorAction Stop |
        Where-Object { $_.Name -eq $InternalName -or $_.DisplayName -eq $DisplayName } |
        Select-Object -First 1

    if ($null -ne $existingTemplate) {
        Write-Success 'Certificate template is already published on this CA.'
        return
    }

    Add-CATemplate -Name $InternalName -Force -ErrorAction Stop
    Write-Success 'Certificate template was published on this CA.'
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
        -CreateIfMissing $CreateTemplateIfMissing
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
    Publish-CertificateTemplate -InternalName $internalTemplateName -DisplayName $templateDisplayName

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
    $publishedTemplate = Get-CATemplate -ErrorAction Stop |
        Where-Object { $_.Name -eq $internalTemplateName -or $_.DisplayName -eq $templateDisplayName } |
        Select-Object -First 1

    if ($null -eq $publishedTemplate) {
        throw 'The certificate template could not be verified as published.'
    }

    $finalMembers = @(
        Get-ADGroupMember -Identity $enrollmentGroup.DistinguishedName -Recursive:$false -ErrorAction Stop |
            Where-Object { $_.ObjectClass -eq 'computer' } |
            Sort-Object -Property Name
    )

    Write-Host ''
    Write-Host 'Certificate template:' -ForegroundColor White
    $publishedTemplate | Format-List Name, DisplayName, OID

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