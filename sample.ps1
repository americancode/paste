.\Configure-SqlAnsible.ps1 `
    -TargetOuDn 'OU=SQL,OU=Servers,DC=compy,DC=local' `
    -ServiceAccountsOuDn 'OU=ServiceAccounts,DC=compy,DC=local' `
    -WinRmIPv4Filter '*'