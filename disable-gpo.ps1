Import-Module GroupPolicy

Set-GPLink `
    -Name 'Servers - Sharepoint' `
    -Target 'OU=Sharepoint,OU=Servers,DC=compy,DC=local' `
    -LinkEnabled No