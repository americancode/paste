# Run as Administrator

$NewComputerName = 'SQLVM01'
$DomainName      = 'compy.local'
$OUPath          = 'OU=SQL,OU=Servers,DC=compy,DC=local'
$DnsServer       = '172.21.4.100'

# Set DNS server on all active adapters
Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
    Set-DnsClientServerAddress `
        -InterfaceIndex $_.InterfaceIndex `
        -ServerAddresses $DnsServer
}

# Verify domain can be resolved
Resolve-DnsName $DomainName -Server $DnsServer

$Credential = Get-Credential -Message "Enter credentials to join $DomainName"

Add-Computer `
    -DomainName $DomainName `
    -OUPath $OUPath `
    -NewName $NewComputerName `
    -Credential $Credential `
    -Restart `
    -Force