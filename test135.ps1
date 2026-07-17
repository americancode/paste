$Servers = @(
    "dc01-mssql-101",
    "dc01-mssql-102"
)

foreach ($Server in $Servers) {
    Write-Host "`n=== $Server ===" -ForegroundColor Cyan

    Resolve-DnsName $Server -ErrorAction Continue

    Test-NetConnection $Server -Port 135
    Test-NetConnection $Server -Port 445

    Test-Connection $Server -Count 1 -ErrorAction Continue
}