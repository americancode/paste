#requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$ComputerName = @(
        'dc01-shpt-101.compy.local',
        'dc01-shpt-102.compy.local'
    ),
    [int]$Port = 5986,
    [int]$TimeoutMilliseconds = 5000
)

$results = foreach ($computer in $ComputerName) {
    $dnsAddresses = @()
    $dnsError = $null
    $tcpSucceeded = $false
    $tcpError = $null
    $tlsSucceeded = $false
    $tlsProtocol = $null
    $certificateSubject = $null
    $certificateIssuer = $null
    $certificateThumbprint = $null
    $certificateNotAfter = $null
    $tlsError = $null

    try {
        $dnsAddresses = @(
            [System.Net.Dns]::GetHostAddresses($computer) |
            ForEach-Object { $_.IPAddressToString }
        )
    }
    catch {
        $dnsError = $_.Exception.Message
    }

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect($computer, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            throw "TCP connection timed out after $TimeoutMilliseconds ms."
        }

        $client.EndConnect($connect)
        $tcpSucceeded = $true

        $ssl = New-Object System.Net.Security.SslStream(
            $client.GetStream(),
            $false,
            { param($sender, $certificate, $chain, $sslPolicyErrors) return $true }
        )

        try {
            $ssl.ReadTimeout = $TimeoutMilliseconds
            $ssl.WriteTimeout = $TimeoutMilliseconds
            $ssl.AuthenticateAsClient($computer)

            $remoteCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $ssl.RemoteCertificate
            )

            $tlsSucceeded = $true
            $tlsProtocol = [string]$ssl.SslProtocol
            $certificateSubject = $remoteCertificate.Subject
            $certificateIssuer = $remoteCertificate.Issuer
            $certificateThumbprint = $remoteCertificate.Thumbprint
            $certificateNotAfter = $remoteCertificate.NotAfter
        }
        catch {
            $tlsError = $_.Exception.Message
        }
        finally {
            if ($null -ne $ssl) {
                $ssl.Dispose()
            }
        }
    }
    catch {
        $tcpError = $_.Exception.Message
    }
    finally {
        $client.Dispose()
    }

    [pscustomobject]@{
        Computer              = $computer
        ResolvedAddresses     = $dnsAddresses -join ', '
        DnsSucceeded          = ($dnsAddresses.Count -gt 0)
        DnsError              = $dnsError
        TcpPort               = $Port
        TcpSucceeded          = $tcpSucceeded
        TcpError              = $tcpError
        TlsSucceeded          = $tlsSucceeded
        TlsProtocol           = $tlsProtocol
        CertificateSubject    = $certificateSubject
        CertificateIssuer     = $certificateIssuer
        CertificateThumbprint = $certificateThumbprint
        CertificateNotAfter   = $certificateNotAfter
        TlsError              = $tlsError
    }
}

$results | Format-List

if (@($results | Where-Object { -not $_.TcpSucceeded }).Count -gt 0) {
    exit 1
}

exit 0