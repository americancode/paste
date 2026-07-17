.\Configure-SqlAnsible.ps1 `
    -TargetOuDn 'OU=SQL,OU=Servers,DC=compy,DC=local' `
    -ServiceAccountsOuDn 'OU=Service Accounts,DC=compy,DC=local' `
    -WinRmIPv4Filter '*'