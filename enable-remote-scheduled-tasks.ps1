# Enable firewall groups required by Invoke-GPUpdate
Enable-NetFirewallRule -DisplayGroup "Remote Scheduled Tasks Management"
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
Enable-NetFirewallRule -DisplayGroup "Remote Service Management"
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"

# Ensure Task Scheduler is running
Start-Service Schedule

# Ensure RPC-related services are running
Start-Service RpcSs
Start-Service Winmgmt

# Apply policy locally
gpupdate.exe /force