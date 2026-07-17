$cred = Get-Credential

Remove-Computer `
    -UnjoinDomainCredential $cred `
    -PassThru `
    -Verbose `
    -Restart `
    -Force