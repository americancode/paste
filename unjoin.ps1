$cred = Get-Credential

Remove-Computer `
    -UnjoinDomainCredential $cred `
    -PassThru `
    -Verbose `
    -Restart `
    -Force


   # ------------
$computerSystem = Get-CimInstance Win32_ComputerSystem

Invoke-CimMethod `
    -InputObject $computerSystem `
    -MethodName UnjoinDomainOrWorkgroup `
    -Arguments @{
        Password        = $null
        UserName        = $null
        FUnjoinOptions  = 0
    }

Invoke-CimMethod `
    -InputObject $computerSystem `
    -MethodName JoinDomainOrWorkgroup `
    -Arguments @{
        Name          = "WORKGROUP"
        FJoinOptions  = 0
    }

Restart-Computer -Force