#requires -Modules ActiveDirectory

param(
    [Parameter(Mandatory)]
    [string]$SourceUser,

    [Parameter(Mandatory)]
    [string]$NewSamAccountName,

    [Parameter(Mandatory)]
    [string]$NewDisplayName,

    [Parameter(Mandatory)]
    [securestring]$Password
)

Import-Module ActiveDirectory

$source = Get-ADUser $SourceUser -Properties *

$newOu = ($source.DistinguishedName -split ',',2)[1]

$upn = "$NewSamAccountName@$((Get-ADDomain).DNSRoot)"

New-ADUser `
    -Name $NewDisplayName `
    -DisplayName $NewDisplayName `
    -GivenName $source.GivenName `
    -Surname $source.Surname `
    -Initials $source.Initials `
    -SamAccountName $NewSamAccountName `
    -UserPrincipalName $upn `
    -Path $newOu `
    -Department $source.Department `
    -Title $source.Title `
    -Company $source.Company `
    -Office $source.Office `
    -OfficePhone $source.OfficePhone `
    -MobilePhone $source.MobilePhone `
    -StreetAddress $source.StreetAddress `
    -City $source.City `
    -State $source.State `
    -PostalCode $source.PostalCode `
    -Country $source.Country `
    -Manager $source.Manager `
    -Description $source.Description `
    -Enabled $true `
    -AccountPassword $Password `
    -ChangePasswordAtLogon $true

$user = Get-ADUser $NewSamAccountName

Get-ADPrincipalGroupMembership $source |
Where-Object {
    $_.Name -ne "Domain Users"
} |
ForEach-Object {
    Add-ADGroupMember `
        -Identity $_ `
        -Members $user `
        -ErrorAction Stop
}

Write-Host "Successfully cloned $SourceUser to $NewSamAccountName"

$password = Read-Host "Password" -AsSecureString

# .\Clone-ADUser.ps1 `
#     -SourceUser "jsmith" `
#     -NewSamAccountName "jdoe" `
#     -NewDisplayName "John Doe" `
#     -Password $password