#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Configures AD CS certificate auto-enrollment for all enabled computers
    beneath a specified server OU.

.DESCRIPTION
    This script:

      1. Finds enabled computers beneath the target OU.
      2. Creates or updates an AD security group containing those computers.
      3. Repairs an existing certificate template for WinRM HTTPS.
      4. Grants the group Read, Enroll, and Autoenroll permissions.
      5. Publishes the template on the local Enterprise CA.
      6. Creates or updates a certificate auto-enrollment GPO.
      7. Links the GPO to the target OU.

    The certificate template must already exist in Active Directory.

    The script is idempotent and can be run again when additional servers are
    added to the OU.

.NOTES
    Run on the Enterprise CA/DC using Windows PowerShell 5.1.
#>

[CmdletBinding()]
param(
    [string]$ServerOu =
        'OU=SQL,OU=Servers,DC=compy,DC=local',

    # Existing certificate template display name or internal name.
    [string]$TemplateName =
        'Ansible WinRM HTTPS',

    [string]$EnrollmentGroupName =
        'WinRM HTTPS SQL Servers',

    # Must be 20 characters or fewer.
    [ValidateLength(1, 20)]
    [string]$EnrollmentGroupSamAccountName =
        'WinRMHTTPS-SQL',

    # Leave empty to create the group in the domain's default Users container.
    [string]$EnrollmentGroupPath = '',

    [string]$AutoEnrollmentGpoName =
        'SQL Servers - Certificate Auto-Enrollment',

    [ValidateRange(2048, 16384)]
    [int]$MinimumKeySize = 2048,

    # Remove computers from the security group if they are no longer beneath
    # the target OU.
    [bool]$RemoveStaleMembers = $true,

    # Restarting CertSvc is normally safe but can be disabled if required.
    [bool]$RestartCertificateService = $true
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Success {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-InfoMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[INFO] $Message"
}

function Write-WarningMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function ConvertTo-LdapFilterValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.
        Replace('\', '\5c').
        Replace('*', '\2a').
        Replace('(', '\28').
        Replace(')', '\29').
        Replace([char]0, '\00')
}

function Get-DomainInformation {
    $domain = Get-ADDomain -ErrorAction Stop

    return [pscustomobject]@{
        DistinguishedName = $domain.DistinguishedName
        DnsRoot           = $domain.DNSRoot
        NetBiosName       = $domain.NetBIOSName
    }
}

function Get-OrCreateEnrollmentGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $escapedSam = ConvertTo-LdapFilterValue -Value $SamAccountName

    $group = Get-ADGroup `
        -LDAPFilter "(sAMAccountName=$escapedSam)" `
        -Properties SID `
        -ErrorAction Stop |
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
        -Description `
            'Computers authorized to auto-enroll for WinRM HTTPS certificates.' `
        -PassThru `
        -ErrorAction Stop

    Write-Success "Created group '$($group.DistinguishedName)'."

    return Get-ADGroup `
        -Identity $group.DistinguishedName `
        -Properties SID `
        -ErrorAction Stop
}

function Sync-OuComputersToGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SearchBase,

        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$Group,

        [Parameter(Mandatory = $true)]
        [bool]$RemoveStale
    )

    $computers = @(
        Get-ADComputer `
            -SearchBase $SearchBase `
            -SearchScope Subtree `
            -Filter * `
            -Properties Enabled `
            -ErrorAction Stop |
        Where-Object {
            $_.Enabled -eq $true
        }
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
        Where-Object {
            $_.ObjectClass -eq 'computer'
        }
    )

    $currentMemberDns = @(
        $currentComputerMembers |
        ForEach-Object {
            $_.DistinguishedName
        }
    )

    $desiredComputerDns = @(
        $computers |
        ForEach-Object {
            $_.DistinguishedName
        }
    )

    $membersToAdd = @(
        $computers |
        Where-Object {
            $_.DistinguishedName -notin $currentMemberDns
        }
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
            Where-Object {
                $_.DistinguishedName -notin $desiredComputerDns
            }
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

function Get-TemplateDirectoryEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $rootDse = [ADSI]'LDAP://RootDSE'
    $configurationNc =
        [string]$rootDse.configurationNamingContext

    $containerDn = @(
        'CN=Certificate Templates'
        'CN=Public Key Services'
        'CN=Services'
        $configurationNc
    ) -join ','

    $searchRoot =
        New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$containerDn"
        )

    $searcher =
        New-Object System.DirectoryServices.DirectorySearcher(
            $searchRoot
        )

    $escapedName = ConvertTo-LdapFilterValue -Value $Name

    $searcher.Filter = @"
(&(objectClass=pKICertificateTemplate)(|(cn=$escapedName)(displayName=$escapedName)))
"@

    $searcher.SearchScope =
        [System.DirectoryServices.SearchScope]::OneLevel

    $result = $searcher.FindOne()

    if ($null -eq $result) {
        throw @"
Certificate template '$Name' was not found in Active Directory.

Open certtmpl.msc and create or duplicate the template first. A suitable
starting point is the built-in Web Server template. Then rerun this script.
"@
    }

    return $result.GetDirectoryEntry()
}

function Get-LocalEnterpriseCa {
    $configurationPath =
        'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'

    if (-not (Test-Path -LiteralPath $configurationPath)) {
        throw 'AD CS Certification Authority is not installed on this server.'
    }

    $activeCaName = (
        Get-ItemProperty `
            -LiteralPath $configurationPath `
            -Name Active `
            -ErrorAction Stop
    ).Active

    if ([string]::IsNullOrWhiteSpace($activeCaName)) {
        throw 'The active Certification Authority name could not be determined.'
    }

    $caPath = Join-Path $configurationPath $activeCaName

    $caProperties = Get-ItemProperty `
        -LiteralPath $caPath `
        -ErrorAction Stop

    $caType = [int]$caProperties.CAType

    # 0 = Enterprise Root CA
    # 1 = Enterprise Subordinate CA
    if ($caType -notin @(0, 1)) {
        throw @"
The local Certification Authority is not an Enterprise CA.

Detected CAType: $caType

Certificate templates and domain auto-enrollment require an Enterprise Root
CA or Enterprise Subordinate CA.
"@
    }

    return [pscustomobject]@{
        Name          = $activeCaName
        Configuration = "$env:COMPUTERNAME\$activeCaName"
        Type          = $caType
    }
}

function Set-MultiValueDirectoryProperty {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.DirectoryEntry]$Entry,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $true)]
        [string[]]$Values
    )

    $Entry.Properties[$PropertyName].Clear()

    foreach ($value in $Values) {
        [void]$Entry.Properties[$PropertyName].Add($value)
    }
}

function Set-TemplateEnrollmentPermissions {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.DirectoryEntry]$Template,

        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$GroupSid
    )

    # Certificate-Enrollment extended right.
    $enrollGuid =
        New-Object Guid '0e10c968-78fb-11d2-90d4-00c04f79dc55'

    # Certificate-AutoEnrollment extended right.
    $autoEnrollGuid =
        New-Object Guid 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    $allow =
        [System.Security.AccessControl.AccessControlType]::Allow

    $security =
        [System.DirectoryServices.ActiveDirectorySecurity]
        $Template.ObjectSecurity

    # Remove existing explicit rules for this group to keep the script
    # repeatable. Inherited permissions are left untouched.
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

    $readRule =
        New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $GroupSid,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
            $allow
        )

    $enrollRule =
        New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $GroupSid,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            $allow,
            $enrollGuid
        )

    $autoEnrollRule =
        New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $GroupSid,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            $allow,
            $autoEnrollGuid
        )

    $security.AddAccessRule($readRule)
    $security.AddAccessRule($enrollRule)
    $security.AddAccessRule($autoEnrollRule)

    $Template.ObjectSecurity = $security
}

function Repair-CertificateTemplate {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.DirectoryEntry]$Template,

        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$EnrollmentGroupSid,

        [Parameter(Mandatory = $true)]
        [int]$KeySize
    )

    # Subject name flags:
    #
    # 0x08000000 = Include DNS name in SAN
    # 0x10000000 = Use DNS name as subject CN
    $certificateNameFlags = 0x18000000

    $Template.Properties['msPKI-Certificate-Name-Flag'].Value =
        $certificateNameFlags

    # Server Authentication EKU.
    $serverAuthenticationOid = '1.3.6.1.5.5.7.3.1'

    Set-MultiValueDirectoryProperty `
        -Entry $Template `
        -PropertyName 'pKIExtendedKeyUsage' `
        -Values @($serverAuthenticationOid)

    try {
        Set-MultiValueDirectoryProperty `
            -Entry $Template `
            -PropertyName 'msPKI-Certificate-Application-Policy' `
            -Values @($serverAuthenticationOid)
    }
    catch {
        Write-WarningMessage @"
Could not update msPKI-Certificate-Application-Policy. The template may use an
older schema version. pKIExtendedKeyUsage was still configured.
"@
    }

    # Add the automatic-enrollment flag while preserving other enrollment flags.
    $currentEnrollmentFlags = 0

    if (
        $null -ne
        $Template.Properties['msPKI-Enrollment-Flag'].Value
    ) {
        $currentEnrollmentFlags =
            [int]$Template.Properties['msPKI-Enrollment-Flag'].Value
    }

    # CT_FLAG_AUTO_ENROLLMENT
    $Template.Properties['msPKI-Enrollment-Flag'].Value =
        ($currentEnrollmentFlags -bor 0x20)

    $Template.Properties['msPKI-Minimal-Key-Size'].Value =
        $KeySize

    # AT_KEYEXCHANGE: signature and encryption.
    $Template.Properties['pKIDefaultKeySpec'].Value = 1

    # No authorized signatures required.
    $Template.Properties['msPKI-RA-Signature'].Value = 0

    # Preserve existing private-key flags but remove exportable-key permission.
    $currentPrivateKeyFlags = 0

    if (
        $null -ne
        $Template.Properties['msPKI-Private-Key-Flag'].Value
    ) {
        $currentPrivateKeyFlags =
            [int]$Template.Properties['msPKI-Private-Key-Flag'].Value
    }

    # CT_FLAG_EXPORTABLE_KEY = 0x10
    $Template.Properties['msPKI-Private-Key-Flag'].Value =
        ($currentPrivateKeyFlags -band (-bnot 0x10))

    Set-TemplateEnrollmentPermissions `
        -Template $Template `
        -GroupSid $EnrollmentGroupSid

    $Template.CommitChanges()
    $Template.RefreshCache()
}

function Publish-CertificateTemplate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InternalName,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    $publishedTemplates = @(
        Get-CATemplate -ErrorAction Stop
    )

    $existingTemplate = $publishedTemplates |
        Where-Object {
            $_.Name -eq $InternalName -or
            $_.DisplayName -eq $DisplayName
        } |
        Select-Object -First 1

    if ($null -ne $existingTemplate) {
        Write-Success 'Certificate template is already published on this CA.'
        return
    }

    Add-CATemplate `
        -Name $InternalName `
        -Force `
        -ErrorAction Stop

    Write-Success 'Certificate template was published on this CA.'
}

function Configure-AutoEnrollmentGpo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName,

        [Parameter(Mandatory = $true)]
        [string]$TargetOu
    )

    $gpo = Get-GPO `
        -Name $GpoName `
        -ErrorAction SilentlyContinue

    if ($null -eq $gpo) {
        $gpo = New-GPO `
            -Name $GpoName `
            -Comment `
                'Enables computer certificate auto-enrollment for WinRM HTTPS.' `
            -ErrorAction Stop

        Write-Success "Created GPO '$GpoName'."
    }
    else {
        Write-Success "Using existing GPO '$GpoName'."
    }

    $autoEnrollmentRegistryKey =
        'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment'

    # AEPolicy 7 enables:
    #   - Automatic enrollment
    #   - Renewal and update
    #   - Updating certificates that use certificate templates
    Set-GPRegistryValue `
        -Name $GpoName `
        -Key $autoEnrollmentRegistryKey `
        -ValueName 'AEPolicy' `
        -Type DWord `
        -Value 7 `
        -ErrorAction Stop

    Write-Success 'Configured computer certificate auto-enrollment policy.'

    $inheritance = Get-GPInheritance `
        -Target $TargetOu `
        -ErrorAction Stop

    $existingLink = @(
        $inheritance.GpoLinks |
        Where-Object {
            $_.DisplayName -eq $GpoName
        }
    )

    if ($existingLink.Count -eq 0) {
        New-GPLink `
            -Name $GpoName `
            -Target $TargetOu `
            -LinkEnabled Yes `
            -ErrorAction Stop |
            Out-Null

        Write-Success "Linked GPO to '$TargetOu'."
    }
    else {
        Set-GPLink `
            -Name $GpoName `
            -Target $TargetOu `
            -LinkEnabled Yes `
            -ErrorAction Stop |
            Out-Null

        Write-Success 'Existing GPO link is enabled.'
    }
}

try {
    Write-Step 'Loading required modules'

    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module ADCSAdministration -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop

    Write-Success 'Required modules loaded.'

    Write-Step 'Validating target OU'

    $targetOu = Get-ADOrganizationalUnit `
        -Identity $ServerOu `
        -ErrorAction Stop

    Write-Success "Target OU found: $($targetOu.DistinguishedName)"

    Write-Step 'Reading domain information'

    $domain = Get-DomainInformation

    if ([string]::IsNullOrWhiteSpace($EnrollmentGroupPath)) {
        $EnrollmentGroupPath =
            "CN=Users,$($domain.DistinguishedName)"
    }

    $groupContainer = Get-ADObject `
        -Identity $EnrollmentGroupPath `
        -ErrorAction Stop

    Write-Success "Enrollment group container: $($groupContainer.DistinguishedName)"

    Write-Step 'Checking the local Enterprise Certification Authority'

    $ca = Get-LocalEnterpriseCa

    Write-Success "Enterprise CA detected: $($ca.Configuration)"

    Write-Step 'Creating or locating the enrollment security group'

    $enrollmentGroup = Get-OrCreateEnrollmentGroup `
        -DisplayName $EnrollmentGroupName `
        -SamAccountName $EnrollmentGroupSamAccountName `
        -Path $EnrollmentGroupPath

    Write-Step 'Synchronizing SQL OU computers into the enrollment group'

    $targetComputers = Sync-OuComputersToGroup `
        -SearchBase $ServerOu `
        -Group $enrollmentGroup `
        -RemoveStale $RemoveStaleMembers

    Write-Step "Locating certificate template '$TemplateName'"

    $template = Get-TemplateDirectoryEntry `
        -Name $TemplateName

    $internalTemplateName =
        [string]$template.Properties['cn'].Value

    $templateDisplayName =
        [string]$template.Properties['displayName'].Value

    Write-Success "Internal template name: $internalTemplateName"
    Write-Success "Template display name: $templateDisplayName"

    Write-Step 'Repairing certificate template settings and permissions'

    $groupSid =
        New-Object System.Security.Principal.SecurityIdentifier(
            $enrollmentGroup.SID.Value
        )

    Repair-CertificateTemplate `
        -Template $template `
        -EnrollmentGroupSid $groupSid `
        -KeySize $MinimumKeySize

    Write-Success 'Certificate template settings and permissions were updated.'

    Write-Step 'Publishing the certificate template'

    Publish-CertificateTemplate `
        -InternalName $internalTemplateName `
        -DisplayName $templateDisplayName

    Write-Step 'Configuring certificate auto-enrollment Group Policy'

    Configure-AutoEnrollmentGpo `
        -GpoName $AutoEnrollmentGpoName `
        -TargetOu $ServerOu

    if ($RestartCertificateService) {
        Write-Step 'Restarting the Certification Authority service'

        Restart-Service `
            -Name CertSvc `
            -Force `
            -ErrorAction Stop

        Start-Sleep -Seconds 3

        $certSvc = Get-Service `
            -Name CertSvc `
            -ErrorAction Stop

        if ($certSvc.Status -ne 'Running') {
            throw 'CertSvc did not return to the Running state.'
        }

        Write-Success 'Certification Authority service is running.'
    }

    Write-Step 'Final verification'

    $publishedTemplate = Get-CATemplate |
        Where-Object {
            $_.Name -eq $internalTemplateName -or
            $_.DisplayName -eq $templateDisplayName
        } |
        Select-Object -First 1

    if ($null -eq $publishedTemplate) {
        throw 'The certificate template could not be verified as published.'
    }

    $finalMembers = @(
        Get-ADGroupMember `
            -Identity $enrollmentGroup.DistinguishedName `
            -Recursive:$false |
        Where-Object {
            $_.ObjectClass -eq 'computer'
        } |
        Sort-Object -Property Name
    )

    Write-Host ''
    Write-Host 'Certificate template:' -ForegroundColor White

    $publishedTemplate |
        Format-List Name, DisplayName, OID

    Write-Host ''
    Write-Host 'Enrollment group:' -ForegroundColor White
    Write-Host "  $($enrollmentGroup.DistinguishedName)"
    Write-Host "  Computer members: $($finalMembers.Count)"

    $finalMembers |
        Select-Object Name, DistinguishedName |
        Format-Table -AutoSize

    Write-Host ''
    Write-Host '============================================================' `
        -ForegroundColor Green
    Write-Host 'WinRM HTTPS certificate enrollment configuration completed.' `
        -ForegroundColor Green
    Write-Host '============================================================' `
        -ForegroundColor Green

    Write-Host ''
    Write-Host 'Important: restart the target servers.' `
        -ForegroundColor Yellow

    Write-Host @'

The computer accounts were added to a new security group. A restart is normally
required for their machine security tokens to include the new group membership.

After restarting each target server, run:

    gpupdate.exe /force
    certutil.exe -pulse

Then verify enrollment:

    Get-ChildItem Cert:\LocalMachine\My |
        Format-List Subject, DnsNameList, EnhancedKeyUsageList,
                    HasPrivateKey, Thumbprint, NotAfter

After the certificate appears, rerun the WinRM HTTPS listener setup script.
'@

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
    Write-Host 'Review the error above. No additional steps will be attempted.' `
        -ForegroundColor Yellow

    exit 1
}
