# File: scripts/windows-network.ps1

# File: scripts/windows-network.ps1

[CmdletBinding()]
param(
    [int]$Port = 0
)

$ErrorActionPreference = "Stop"

Write-Host "=== TCP listeners ==="
if ($Port -eq 0) {
    Get-NetTCPConnection -State Listen |
        Sort-Object LocalPort |
        Format-Table LocalAddress, LocalPort, State, OwningProcess
}
else {
    Get-NetTCPConnection -State Listen -LocalPort $Port |
        Format-Table LocalAddress, LocalPort, State, OwningProcess
}

Write-Host "`n=== UDP endpoints ==="
if ($Port -eq 0) {
    Get-NetUDPEndpoint |
        Sort-Object LocalPort |
        Format-Table LocalAddress, LocalPort, OwningProcess
}
else {
    Get-NetUDPEndpoint -LocalPort $Port |
        Format-Table LocalAddress, LocalPort, OwningProcess
}

Write-Host "`n=== netstat listeners ==="
netstat -ano -p tcp | Select-String "LISTENING"

Write-Host "`n=== Process names for visible TCP listeners ==="

$seen = @{}

Get-NetTCPConnection -State Listen |
    Select-Object -ExpandProperty OwningProcess -Unique |
    ForEach-Object {
        $pidValue = [int]$_

        if ($seen.ContainsKey($pidValue)) {
            return
        }

        $seen[$pidValue] = $true

        try {
            $process = Get-Process -Id $pidValue -ErrorAction Stop

            [PSCustomObject]@{
                PID      = $process.Id
                Process  = $process.ProcessName
                Path     = $process.Path
            }
        }
        catch {
            [PSCustomObject]@{
                PID      = $pidValue
                Process  = "Unavailable"
                Path     = "Unavailable"
            }
        }
    } |
    Format-Table -AutoSize

Write-Host "`nInspection completed."
