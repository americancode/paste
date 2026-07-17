$cred = Get-Credential
Rename-Computer `
    -NewName "NEW-COMPUTER-NAME" `
    -DomainCredential $cred `
    -Restart