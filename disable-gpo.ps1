Import-Module GroupPolicy

Set-GPLink `
    -Name 'Servers - SharePoint' `
    -Target 'OU=Sharepoint,OU=Servers,DC=yourdomain,DC=com' `
    -LinkEnabled No