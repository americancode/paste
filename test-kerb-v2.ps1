#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Read-only post-reboot validation for SharePoint WinRM over HTTPS.

.DESCRIPTION
    Validates the corrected GPO/scheduled-task deployment without changing the node.
    Checks applied GPO, auto-enrollment policy, scheduled task and logs, certificate,
    WinRM service/listener, TCP 5986, firewall coverage, and a local HTTPS WSMan test.

.NOTES
    Designed for Windows PowerShell 5.1.
    Exit code 0 = all required checks passed.
    Exit code 1 = one or more required checks failed.
#>

[CmdletBinding()]
param(
    [string]$ExpectedGpoName = 'Servers - Sharepoint',
    [string]$TaskName = 'Configure Ansible WinRM HTTPS',
    [string]$TemplateDisplayName = 'Ansible WinRM HTTPS',
    [string]$TemplateInternalName = 'AnsibleWinRMHTTPS',
    [string]$InstallLogPath = 'C:\ProgramData\Ansible-WinRM\Install-WinRmHttpsTask.log',
    [string]$ConfigureLogPath = 'C:\ProgramData\Ansible-WinRM\Configure-WinRmHttps.log',
    [ValidateRange(1, 500)]
    [int]$LogTail = 80,
    [switch]$DiagnosticSkipRevocationCheck
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$script:Failures = 0
$script:Warnings = 0

function Write-Section {
    param([Parameter(Mandatory)][string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Pass {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([Parameter(Mandatory)][string]$Message)
    $script:Warnings++
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([Parameter(Mandatory)][string]$Message)
    $script:Failures++
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-Info {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[INFO] $Message"
}

function Get-NodeIdentity {
    Write-Section 'Node identity'
    try {
        $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if (-not $computer.PartOfDomain) {
            Write-Fail 'Computer is not joined to an Active Directory domain.'
            return $null
        }

        $fqdn = ('{0}.{1}' -f $computer.DNSHostName, $computer.Domain).
            TrimEnd('.').ToLowerInvariant()

        Write-Pass "Domain joined: $($computer.Domain)"
        Write-Pass "Computer FQDN: $fqdn"
        return $fqdn
    }
    catch {
        Write-Fail "Unable to determine node identity: $($_.Exception.Message)"
        return $null
    }
}

function Test-AppliedGpo {
    Write-Section 'Applied computer Group Policy'
    try {
        $output = @(& gpresult.exe /R /SCOPE COMPUTER 2>&1)
        $exitCode = $LASTEXITCODE
        $text = $output -join [Environment]::NewLine

        if ($exitCode -ne 0) {
            Write-Fail "gpresult failed with exit code $exitCode."
            $output | ForEach-Object { Write-Host "  $_" }
            return
        }

        if ([string]::IsNullOrWhiteSpace($ExpectedGpoName)) {
            Write-Warn 'ExpectedGpoName is empty; the applied GPO name was not validated.'
        }
        elseif ($text -match [regex]::Escape($ExpectedGpoName)) {
            Write-Pass "GPO '$ExpectedGpoName' is applied."
        }
        else {
            Write-Fail "GPO '$ExpectedGpoName' is not listed by gpresult."
            Write-Info 'Applied GPO names can be reviewed with: gpresult /R /SCOPE COMPUTER'
        }
    }
    catch {
        Write-Fail "Unable to run gpresult: $($_.Exception.Message)"
    }
}

function Test-AutoEnrollmentPolicy {
    Write-Section 'Certificate auto-enrollment policy'
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment'

    try {
        $value = Get-ItemPropertyValue -LiteralPath $path -Name AEPolicy -ErrorAction Stop
        Write-Info "AEPolicy: $value"
        if ([int]$value -gt 0) {
            Write-Pass 'Computer certificate auto-enrollment policy is enabled.'
        }
        else {
            Write-Fail 'AEPolicy is zero.'
        }
    }
    catch {
        Write-Fail "Unable to read AEPolicy: $($_.Exception.Message)"
    }
}

function Test-EnrollmentTemplateVisibility {
    Write-Section 'Certificate template visibility'
    try {
        $output = @(& certutil.exe -template 2>&1)
        $exitCode = $LASTEXITCODE
        $text = $output -join [Environment]::NewLine

        if ($exitCode -ne 0) {
            $hexValue = ([int64]$exitCode -band [int64]4294967295)
            $hex = '0x{0:X8}' -f $hexValue
            Write-Warn "certutil -template failed with exit code $exitCode ($hex). This check is advisory; certificate and listener checks remain authoritative."
            $output | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" }
            return
        }

        if (
            $text -match [regex]::Escape($TemplateInternalName) -or
            $text -match [regex]::Escape($TemplateDisplayName)
        ) {
            Write-Pass "Enrollment client can see template '$TemplateInternalName'."
        }
        else {
            Write-Fail "Enrollment client cannot see template '$TemplateInternalName'."
        }
    }
    catch {
        Write-Fail "Unable to enumerate certificate templates: $($_.Exception.Message)"
    }
}

function Test-DeploymentTask {
    Write-Section 'WinRM configuration scheduled task'
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop

        Write-Info "State: $($task.State)"
        Write-Info "Last run: $($info.LastRunTime)"
        $taskResult = [int64]$info.LastTaskResult
        $taskResultHex = '0x{0:X8}' -f ($taskResult -band [int64]4294967295)
        Write-Info "Last result: $taskResult ($taskResultHex)"
        Write-Info "Next run: $($info.NextRunTime)"

        if ($task.Settings.Enabled) {
            Write-Pass "Scheduled task '$TaskName' is enabled."
        }
        else {
            Write-Fail "Scheduled task '$TaskName' is disabled."
        }

        switch ([int64]$info.LastTaskResult) {
            0          { Write-Pass 'Scheduled task last completed successfully.' }
            267009     { Write-Warn 'Scheduled task is currently running (0x00041301).' }
            267011     { Write-Warn 'Scheduled task has not yet run (0x00041303).' }
            default    { Write-Fail "Scheduled task last result is $($info.LastTaskResult)." }
        }

        $task.Actions | Format-List Execute, Arguments, WorkingDirectory
        $task.Triggers | Format-List *
    }
    catch {
        Write-Fail "Scheduled task '$TaskName' was not found or could not be read: $($_.Exception.Message)"
    }
}

function Show-DeploymentLogs {
    Write-Section 'Deployment logs'
    foreach ($path in @($InstallLogPath, $ConfigureLogPath)) {
        Write-Host ''
        Write-Info "Log: $path"
        if (Test-Path -LiteralPath $path) {
            try {
                Get-Content -LiteralPath $path -Tail $LogTail -ErrorAction Stop |
                    ForEach-Object { Write-Host "  $_" }
                Write-Pass "Log exists: $path"
            }
            catch {
                Write-Warn "Could not read '$path': $($_.Exception.Message)"
            }
        }
        else {
            Write-Warn "Log does not exist: $path"
        }
    }
}

function Get-CertificateDnsNames {
    param([Parameter(Mandatory)]$Certificate)
    $names = @()
    try {
        foreach ($name in @($Certificate.DnsNameList)) {
            if ($null -ne $name.PSObject.Properties['Unicode']) {
                $names += [string]$name.Unicode
            }
            else {
                $names += [string]$name
            }
        }
    }
    catch { }
    return @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Test-ServerAuthenticationEku {
    param([Parameter(Mandatory)]$Certificate)
    $serverAuthOid = '1.3.6.1.5.5.7.3.1'
    try {
        $extension = $Certificate.Extensions |
            Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
            Select-Object -First 1
        if ($null -eq $extension) { return $false }

        $eku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension `
            -ArgumentList $extension, $extension.Critical
        return [bool](@($eku.EnhancedKeyUsages | Where-Object { $_.Value -eq $serverAuthOid }).Count)
    }
    catch {
        return $false
    }
}

function Test-CertificateHostname {
    param(
        [Parameter(Mandatory)]$Certificate,
        [Parameter(Mandatory)][string]$Fqdn
    )

    $required = $Fqdn.TrimEnd('.').ToLowerInvariant()
    foreach ($name in @(Get-CertificateDnsNames -Certificate $Certificate)) {
        if ($name.TrimEnd('.').ToLowerInvariant() -eq $required) { return $true }
    }

    try {
        $name = $Certificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName,
            $false
        )
        return $name.TrimEnd('.').ToLowerInvariant() -eq $required
    }
    catch {
        return $false
    }
}

function Test-MachineCertificate {
    param([Parameter(Mandatory)][string]$Fqdn)
    Write-Section 'Machine certificate'

    try {
        $now = Get-Date
        $results = foreach ($cert in @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop)) {
            $valid = $cert.NotBefore -le $now -and $cert.NotAfter -gt $now
            $eku = Test-ServerAuthenticationEku -Certificate $cert
            $hostMatch = Test-CertificateHostname -Certificate $cert -Fqdn $Fqdn
            $suitable = $cert.HasPrivateKey -and $valid -and $eku -and $hostMatch

            [pscustomobject]@{
                Suitable       = $suitable
                Subject        = $cert.Subject
                Thumbprint     = $cert.Thumbprint
                HasPrivateKey  = $cert.HasPrivateKey
                Valid          = $valid
                ServerAuthEKU  = $eku
                HostnameMatch  = $hostMatch
                DNSNames       = (Get-CertificateDnsNames -Certificate $cert) -join ', '
                NotAfter       = $cert.NotAfter
            }
        }

        $results | Sort-Object Suitable, NotAfter -Descending | Format-Table -Wrap -AutoSize
        $suitableCerts = @($results | Where-Object Suitable)

        if ($suitableCerts.Count -gt 0) {
            Write-Pass "$($suitableCerts.Count) suitable WinRM HTTPS certificate(s) found."
            return @($suitableCerts)
        }

        Write-Fail 'No suitable machine certificate was found.'
        return @()
    }
    catch {
        Write-Fail "Unable to inspect LocalMachine\My: $($_.Exception.Message)"
        return @()
    }
}

function Test-WinRm {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)]$SuitableCertificates
    )

    Write-Section 'WinRM service and HTTPS listener'

    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
        Write-Info "State: $($service.State)"
        Write-Info "Start mode: $($service.StartMode)"

        if ($service.State -eq 'Running') { Write-Pass 'WinRM service is running.' }
        else { Write-Fail 'WinRM service is not running.' }

        if ($service.StartMode -eq 'Auto') { Write-Pass 'WinRM service start mode is Automatic.' }
        else { Write-Warn "WinRM service start mode is '$($service.StartMode)'." }
    }
    catch {
        Write-Fail "Unable to inspect WinRM service: $($_.Exception.Message)"
    }

    try {
        Import-Module Microsoft.WSMan.Management -ErrorAction SilentlyContinue
        $listeners = @(Get-WSManInstance -ResourceURI 'winrm/config/listener' -Enumerate -ErrorAction Stop)
        $https = @($listeners | Where-Object { [string]$_.Transport -eq 'HTTPS' })

        $listeners |
            Select-Object Address, Transport, Port, Hostname, CertificateThumbprint, Enabled |
            Format-Table -Wrap -AutoSize

        if ($https.Count -eq 0) {
            Write-Fail 'No WinRM HTTPS listener exists.'
        }
        else {
            Write-Pass "$($https.Count) WinRM HTTPS listener(s) found."
            foreach ($listener in $https) {
                $hostProperty = $listener.PSObject.Properties['Hostname']
                $thumbProperty = $listener.PSObject.Properties['CertificateThumbprint']

                $listenerHost = if ($null -ne $hostProperty) {
                    ([string]$hostProperty.Value).TrimEnd('.').ToLowerInvariant()
                }
                else { '' }

                $thumb = if ($null -ne $thumbProperty) {
                    ([string]$thumbProperty.Value).Replace(' ', '').ToUpperInvariant()
                }
                else { '' }

                if ($listenerHost -eq $Fqdn) { Write-Pass "Listener hostname matches $Fqdn." }
                else { Write-Fail "Listener hostname '$listenerHost' does not match '$Fqdn'." }

                if ([string]::IsNullOrWhiteSpace($thumb)) {
                    Write-Fail 'HTTPS listener did not expose a CertificateThumbprint property.'
                    continue
                }

                $cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$thumb" -ErrorAction SilentlyContinue
                if ($null -ne $cert) { Write-Pass "Listener certificate $thumb exists." }
                else { Write-Fail "Listener certificate $thumb is missing." }

                $suitableThumbs = @(
                    $SuitableCertificates |
                    ForEach-Object {
                        $property = $_.PSObject.Properties['Thumbprint']
                        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                            ([string]$property.Value).Replace(' ', '').ToUpperInvariant()
                        }
                    }
                )
                if ($suitableThumbs -contains $thumb) {
                    Write-Pass 'Listener uses a certificate that passed all suitability checks.'
                }
                else {
                    Write-Fail 'Listener certificate did not pass all suitability checks.'
                }
            }
        }
    }
    catch {
        Write-Fail "Unable to enumerate WinRM listeners: $($_.Exception.Message)"
    }

    try {
        $tcp = @(Get-NetTCPConnection -LocalPort 5986 -State Listen -ErrorAction SilentlyContinue)
        if ($tcp.Count -gt 0) { Write-Pass 'TCP 5986 is listening.' }
        else { Write-Fail 'TCP 5986 is not listening.' }
    }
    catch {
        Write-Fail "Unable to inspect TCP 5986: $($_.Exception.Message)"
    }

    try {
        $result = Test-NetConnection -ComputerName $Fqdn -Port 5986 -WarningAction SilentlyContinue
        if ($result.TcpTestSucceeded) { Write-Pass "TCP connection to $Fqdn`:5986 succeeded." }
        else { Write-Fail "TCP connection to $Fqdn`:5986 failed." }
    }
    catch {
        Write-Fail "TCP test failed: $($_.Exception.Message)"
    }

    try {
        $null = Test-WSMan -ComputerName $Fqdn -UseSSL -ErrorAction Stop
        Write-Pass "Test-WSMan over HTTPS succeeded for $Fqdn with full certificate validation."
    }
    catch {
        $message = $_.Exception.Message
        if ($message -match '12175|revocation|revoked') {
            Write-Warn "Full certificate validation could not check revocation status: $message"

            try {
                $sessionOption = New-PSSessionOption -SkipRevocationCheck
                $session = $null

                try {
                    $session = New-PSSession `
                        -ComputerName $Fqdn `
                        -UseSSL `
                        -Authentication Negotiate `
                        -SessionOption $sessionOption `
                        -ErrorAction Stop

                    Write-Warn 'WinRM HTTPS succeeds when only revocation checking is skipped. The listener, certificate trust, hostname, authentication, and remoting endpoint are working; CRL/CDP reachability still needs repair.'
                }
                finally {
                    if ($null -ne $session) {
                        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                Write-Fail "WinRM HTTPS also failed when only revocation checking was skipped: $($_.Exception.Message)"
            }
        }
        else {
            Write-Fail "Test-WSMan over HTTPS failed: $message"
        }
    }
}

function Test-Firewall5986 {
    Write-Section 'Firewall access for TCP 5986'
    try {
        $matches = @()
        foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
            foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
                $protocol = [string]$filter.Protocol
                $port = [string]$filter.LocalPort
                if (($protocol -eq 'TCP' -or $protocol -eq '6') -and ($port -eq '5986' -or $port -eq 'Any')) {
                    $addresses = @($rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue |
                        ForEach-Object { $_.RemoteAddress })
                    $matches += [pscustomobject]@{
                        DisplayName   = $rule.DisplayName
                        Profile       = $rule.Profile
                        LocalPort     = $port
                        RemoteAddress = $addresses -join ', '
                    }
                    break
                }
            }
        }

        if ($matches.Count -gt 0) {
            Write-Pass 'At least one enabled inbound allow rule covers TCP 5986.'
            $matches | Format-Table -Wrap -AutoSize
        }
        else {
            Write-Fail 'No enabled inbound allow rule covers TCP 5986.'
        }
    }
    catch {
        Write-Fail "Unable to inspect firewall rules: $($_.Exception.Message)"
    }
}

Write-Host ''
Write-Host 'SharePoint WinRM HTTPS node validation' -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "Started:  $(Get-Date)"

$fqdn = Get-NodeIdentity
Test-AppliedGpo
Test-AutoEnrollmentPolicy
Test-EnrollmentTemplateVisibility
Test-DeploymentTask
Show-DeploymentLogs

$suitable = @()
if (-not [string]::IsNullOrWhiteSpace($fqdn)) {
    $suitable = @(Test-MachineCertificate -Fqdn $fqdn)
    Test-WinRm -Fqdn $fqdn -SuitableCertificates $suitable
}
else {
    Write-Fail 'Certificate and WinRM hostname checks were skipped because the FQDN is unavailable.'
}

Test-Firewall5986

Write-Section 'Final result'
Write-Host "Failures: $script:Failures"
Write-Host "Warnings: $script:Warnings"

if ($script:Failures -eq 0) {
    Write-Pass 'This node is ready for WinRM over HTTPS.'
    exit 0
}

Write-Fail 'This node is not ready for WinRM over HTTPS.'
Write-Host 'Review the [FAIL] messages and the deployment logs above.' -ForegroundColor Yellow
exit 1