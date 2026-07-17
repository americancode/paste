$NewComputerName = 'REPLACE_ME'
$DomainName      = 'compy.local'
$OUPath          = 'OU=SQL,OU=Servers,DC=compy,DC=local'

$Credential = Get-Credential -Message "Enter credentials allowed to join $DomainName"

Add-Computer `
    -DomainName $DomainName `
    -OUPath $OUPath `
    -NewName $NewComputerName `
    -Credential $Credential `
    -Restart `
    -Force