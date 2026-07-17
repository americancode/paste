# Run as Administrator

# Enable Remote Desktop
Set-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' `
    -Value 0

# Require Network Level Authentication (recommended)
Set-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'UserAuthentication' `
    -Value 1

# Enable the Remote Desktop firewall rules
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Ensure the Remote Desktop Services service is running
Set-Service -Name TermService -StartupType Automatic
Start-Service -Name TermService

Write-Host "Remote Desktop has been enabled."