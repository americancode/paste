#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ExpectedGpoName = 'Servers - SharePoint',

    # Use "*" temporarily for testing, then restrict this to the AWX
    # Kubernetes node/egress subnet once connectivity is confirmed.
    [string]$AllowedRemoteAddress = '*',

    [int]$CertificateWaitSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$logDirectory = 'C:\ProgramData\Ansible-WinRM'
$logPath = Join-Path $logDirectory 'Target-WinRM-HTTPS-Setup.log'

New-Item `
    -Path $logDirectory `
    -ItemType Directory `
    -Force |
    Out-Null

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '{0:u} [{1}] {2}' -f (Get-Date), $Level, $Message

    Write-Host $line

    Add-Content `
        -LiteralPath $logPath `
        -Value $line `
        -Encoding UTF8
}

function Get-ComputerFqdn {
    $computerSystem = Get-CimInstance Win32_ComputerSystem

    if (-not $computerSystem.PartOfDomain) {
        throw 'This computer is not joined to an Active Directory domain.'
    }

    return '{0}.{1}' -f `
        $env:COMPUTERNAME.ToLowerInvariant(),
        $computerSystem.Domain.ToLowerInvariant()
}

function Test-CertificateHostname {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [string]$Fqdn
    )

    $fqdnLower = $Fqdn.ToLowerInvariant()

    $dnsNames = @(
        $Certificate.DnsNameList |
        ForEach-Object {
            $_.Unicode.ToLowerInvariant()
        }
    )

    if ($dnsNames -contains $fqdnLower) {
        return $true
    }

    # Fall back to the certificate subject CN when no SAN match exists.
    if ($Certificate.Subject -match '(?i)(?:^|,\s*)CN=([^,]+)') {
        $commonName = $Matches[1].Trim().ToLowerInvariant()

        if ($commonName -eq $fqdnLower) {
            return $true
        }
    }

    return $false
}

function Test-ServerAuthenticationEku {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # Server Authentication EKU OID
    $serverAuthenticationOid = '1.3.6.1.5.5.7.3.1'

    foreach ($extension in $Certificate.Extensions) {
        if ($extension.Oid.Value -ne '2.5.29.37') {
            continue
        }

        $ekuExtension =
            [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension

        if ($ekuExtension.EnhancedKeyUsages.Value -contains $serverAuthenticationOid) {
            return $true
        }
    }

    return $false
}

function Get-SuitableWinRmCertificate {
    param(
        [Parameter(Mandatory)]
        [string]$Fqdn
    )

    $now = Get-Date

    $certificates = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            $_.HasPrivateKey -and
            $_.NotBefore -le $now -and
            $_.NotAfter -gt $now -and
            (Test-ServerAuthenticationEku -Certificate $_) -and
            (Test-CertificateHostname -Certificate $_ -Fqdn $Fqdn)
        } |
        Sort-Object NotAfter -Descending

    return $certificates | Select-Object -First 1
}

function Get-HttpsWinRmListener {
    $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue

    return $listeners |
        Where-Object {
            $_.Keys -contains 'Transport=HTTPS'
        } |
        Select-Object -First 1
}

function Ensure-WinRmService {
    Write-Log 'Configuring the WinRM service.'

    Set-Service `
        -Name WinRM `
        -StartupType Automatic

    Start-Service `
        -Name WinRM

    # Configure the base WinRM service and HTTP listener if needed.
    & winrm quickconfig -quiet |
        ForEach-Object {
            Write-Log "winrm quickconfig: $_"
        }
}

function Ensure-WinRmHttpsListener {
    param(
        [Parameter(Mandatory)]
        [string]$Fqdn,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $thumbprint = $Certificate.Thumbprint.Replace(' ', '').ToUpperInvariant()
    $listener = Get-HttpsWinRmListener

    if ($listener) {
        $currentThumbprint = [string]$listener.CertificateThumbprint
        $currentHostname = [string]$listener.Hostname

        if (
            $currentThumbprint.Replace(' ', '').ToUpperInvariant() -eq $thumbprint -and
            $currentHostname.ToLowerInvariant() -eq $Fqdn.ToLowerInvariant()
        ) {
            Write-Log "The WinRM HTTPS listener already uses certificate $thumbprint."
            return
        }

        Write-Log `
            "Removing the existing HTTPS listener because its hostname or certificate differs." `
            'WARN'

        Remove-Item `
            -LiteralPath $listener.PSPath `
            -Recurse `
            -Force
    }

    Write-Log "Creating the WinRM HTTPS listener for $Fqdn."

    $selector = @{
        Address   = '*'
        Transport = 'HTTPS'
    }

    $values = @{
        Hostname              = $Fqdn
        CertificateThumbprint = $thumbprint
        Enabled               = $true
    }

    New-Item `
        -Path WSMan:\localhost\Listener `
        -SelectorSet $selector `
        -ValueSet $values `
        -Force |
        Out-Null
}

function Ensure-WinRmHttpsFirewallRule {
    param(
        [Parameter(Mandatory)]
        [string]$RemoteAddress
    )

    $ruleName = 'Ansible WinRM HTTPS 5986'

    $existingRule = Get-NetFirewallRule `
        -DisplayName $ruleName `
        -ErrorAction SilentlyContinue

    if (-not $existingRule) {
        Write-Log "Creating firewall rule '$ruleName'."

        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Description 'Allow Ansible WinRM HTTPS traffic' `
            -Direction Inbound `
            -Action Allow `
            -Enabled True `
            -Profile Domain `
            -Protocol TCP `
            -LocalPort 5986 `
            -RemoteAddress $RemoteAddress |
            Out-Null
    }
    else {
        Write-Log "Updating firewall rule '$ruleName'."

        Set-NetFirewallRule `
            -DisplayName $ruleName `
            -Enabled True `
            -Profile Domain `
            -Direction Inbound `
            -Action Allow |
            Out-Null

        Set-NetFirewallPortFilter `
            -AssociatedNetFirewallRule $existingRule `
            -Protocol TCP `
            -LocalPort 5986 |
            Out-Null

        Set-NetFirewallAddressFilter `
            -AssociatedNetFirewallRule $existingRule `
            -RemoteAddress $RemoteAddress |
            Out-Null
    }
}

function Show-GpoStatus {
    Write-Log "Checking whether GPO '$ExpectedGpoName' is applied."

    $gpResult = & gpresult.exe /R /SCOPE COMPUTER 2>&1
    $gpResultText = $gpResult -join [Environment]::NewLine

    if ($gpResultText -match [regex]::Escape($ExpectedGpoName)) {
        Write-Log "GPO '$ExpectedGpoName' appears in computer policy results."
    }
    else {
        Write-Log `
            "GPO '$ExpectedGpoName' was not found in gpresult output." `
            'WARN'
    }
}

function Show-Diagnostics {
    param(
        [Parameter(Mandatory)]
        [string]$Fqdn,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    Write-Host ''
    Write-Host '---------------- WinRM HTTPS diagnostics ----------------'
    Write-Host "Computer FQDN:       $Fqdn"
    Write-Host "Certificate subject: $($Certificate.Subject)"
    Write-Host "Certificate issuer:  $($Certificate.Issuer)"
    Write-Host "Certificate expires: $($Certificate.NotAfter)"
    Write-Host "Certificate thumb:   $($Certificate.Thumbprint)"
    Write-Host ''

    Write-Host 'WinRM listeners:'
    & winrm enumerate winrm/config/listener

    Write-Host ''
    Write-Host 'TCP 5986 listener:'

    Get-NetTCPConnection `
        -LocalPort 5986 `
        -State Listen `
        -ErrorAction SilentlyContinue |
        Format-Table `
            LocalAddress,
            LocalPort,
            State,
            OwningProcess `
            -AutoSize

    Write-Host ''
    Write-Host 'Local connectivity test:'

    Test-NetConnection `
        -ComputerName localhost `
        -Port 5986

    Write-Host ''
    Write-Host 'Firewall rule:'

    Get-NetFirewallRule `
        -DisplayName 'Ansible WinRM HTTPS 5986' `
        -ErrorAction SilentlyContinue |
        Get-NetFirewallPortFilter |
        Format-List

    Get-NetFirewallRule `
        -DisplayName 'Ansible WinRM HTTPS 5986' `
        -ErrorAction SilentlyContinue |
        Get-NetFirewallAddressFilter |
        Format-List

    Write-Host ''
    Write-Host "Log file: $logPath"
}

try {
    Write-Log 'Starting WinRM HTTPS target configuration.'

    Show-GpoStatus

    $fqdn = Get-ComputerFqdn
    Write-Log "Detected computer FQDN: $fqdn"

    Ensure-WinRmService

    Write-Log 'Triggering computer certificate auto-enrollment.'
    & certutil.exe -pulse |
        ForEach-Object {
            Write-Log "certutil: $_"
        }

    $deadline = (Get-Date).AddSeconds($CertificateWaitSeconds)
    $certificate = $null

    do {
        $certificate = Get-SuitableWinRmCertificate -Fqdn $fqdn

        if (-not $certificate) {
            Write-Log `
                "Waiting for a certificate valid for $fqdn..." `
                'WARN'

            Start-Sleep -Seconds 5
        }
    }
    until ($certificate -or (Get-Date) -ge $deadline)

    if (-not $certificate) {
        Write-Log `
            "No suitable machine certificate was found for $fqdn." `
            'ERROR'

        Write-Host ''
        Write-Host 'Available Local Computer certificates:' -ForegroundColor Yellow

        Get-ChildItem Cert:\LocalMachine\My |
            Select-Object `
                Subject,
                Issuer,
                HasPrivateKey,
                NotBefore,
                NotAfter,
                Thumbprint,
                @{
                    Name = 'DNSNames'
                    Expression = {
                        ($_.DnsNameList.Unicode -join ', ')
                    }
                },
                @{
                    Name = 'EKUs'
                    Expression = {
                        ($_.EnhancedKeyUsageList.FriendlyName -join ', ')
                    }
                } |
            Format-List

        throw @"
No valid WinRM HTTPS certificate was found.

The certificate must:
- Be in Cert:\LocalMachine\My
- Have a private key
- Be currently valid
- Include Server Authentication EKU
- Include '$fqdn' in its SAN or subject CN

Check the AD CS template, template publication, and the computer account's
Read, Enroll, and Autoenroll permissions.
"@
    }

    Write-Log `
        "Selected certificate $($certificate.Thumbprint), expiring $($certificate.NotAfter)."

    Ensure-WinRmHttpsListener `
        -Fqdn $fqdn `
        -Certificate $certificate

    Ensure-WinRmHttpsFirewallRule `
        -RemoteAddress $AllowedRemoteAddress

    Restart-Service `
        -Name WinRM `
        -Force

    Start-Sleep -Seconds 3

    $tcpListener = Get-NetTCPConnection `
        -LocalPort 5986 `
        -State Listen `
        -ErrorAction SilentlyContinue

    if (-not $tcpListener) {
        throw 'WinRM was configured, but no process is listening on TCP 5986.'
    }

    Write-Log 'WinRM HTTPS is listening successfully on TCP 5986.'

    Show-Diagnostics `
        -Fqdn $fqdn `
        -Certificate $certificate
}
catch {
    Write-Log $_.Exception.Message 'ERROR'

    Write-Host ''
    Write-Host 'Configuration failed.' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ''
    Write-Host "Review the log at: $logPath"

    exit 1
}
