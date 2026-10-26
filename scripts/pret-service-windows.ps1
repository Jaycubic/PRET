<#
.SYNOPSIS
    PRET Web UI — Windows Service & Process Manager
.DESCRIPTION
    Provides service lifecycle management (Start, Stop, Status, Install-Task, Uninstall-Task)
    for running the PRET Web UI backend on Windows.
.EXAMPLE
    .\pret-service-windows.ps1 Start
    .\pret-service-windows.ps1 Status
    .\pret-service-windows.ps1 Install-Task
#>

param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("Start", "Stop", "Status", "Restart", "Install-Task", "Uninstall-Task")]
    [string]$Action
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$BackendDir = Join-Path $ProjectRoot "backend"
$PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
$TaskName = "PRET-Web-UI"

if (-not $PythonExe) {
    Write-Error "Python was not found in PATH. Please install Python 3.10+ and ensure it is in PATH."
    exit 1
}

function Get-PretProcess {
    Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -match "uvicorn" -and $_.CommandLine -match "app.main:app"
    }
}

switch ($Action) {
    "Start" {
        $existing = Get-PretProcess
        if ($existing) {
            Write-Host "PRET Web UI is already running (PID: $($existing.ProcessId))." -ForegroundColor Yellow
            return
        }

        Write-Host "Starting PRET Web UI in background..." -ForegroundColor Cyan
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $PythonExe
        $startInfo.Arguments = "-m uvicorn app.main:app --host 0.0.0.0 --port 8443"
        $startInfo.WorkingDirectory = $BackendDir
        $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $startInfo.CreateNoWindow = $true
        $startInfo.UseShellExecute = $true

        $proc = [System.Diagnostics.Process]::Start($startInfo)
        Start-Sleep -Seconds 2

        $check = Get-PretProcess
        if ($check) {
            Write-Host "PRET Web UI successfully started (PID: $($check.ProcessId))." -ForegroundColor Green
            Write-Host "Accessible at: http://0.0.0.0:8443/" -ForegroundColor Green
        } else {
            Write-Error "Failed to start PRET Web UI. Check logs in $BackendDir."
        }
    }

    "Stop" {
        $procs = Get-PretProcess
        if (-not $procs) {
            Write-Host "PRET Web UI is not currently running." -ForegroundColor Yellow
            return
        }
        foreach ($p in $procs) {
            Write-Host "Stopping PRET Web UI (PID: $($p.ProcessId))..." -ForegroundColor Cyan
            Stop-Process -Id $p.ProcessId -Force
        }
        Write-Host "PRET Web UI stopped." -ForegroundColor Green
    }

    "Restart" {
        & $MyInvocation.MyCommand.Path Stop
        Start-Sleep -Seconds 1
        & $MyInvocation.MyCommand.Path Start
    }

    "Status" {
        $proc = Get-PretProcess
        if ($proc) {
            Write-Host "PRET Web UI is RUNNING (PID: $($proc.ProcessId))." -ForegroundColor Green
            try {
                $health = Invoke-RestMethod -Uri "http://0.0.0.0:8443/healthz" -TimeoutSec 3
                Write-Host "Health Check: OK ($($health | ConvertTo-Json -Compress))" -ForegroundColor Green
            } catch {
                Write-Host "Health Check: Endpoint not responding ($($_.Exception.Message))" -ForegroundColor Yellow
            }
        } else {
            Write-Host "PRET Web UI is STOPPED." -ForegroundColor DarkGray
        }
    }

    "Install-Task" {
        $taskCmd = "$PythonExe -m uvicorn app.main:app --host 0.0.0.0 --port 8443"
        $action = New-ScheduledTaskAction -Execute $PythonExe -Argument "-m uvicorn app.main:app --host 0.0.0.0 --port 8443" -WorkingDirectory $BackendDir
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Description "PRET Web UI background service" -Force
        Write-Host "Scheduled task '$TaskName' registered to launch at startup." -ForegroundColor Green
    }

    "Uninstall-Task" {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Scheduled task '$TaskName' removed." -ForegroundColor Green
    }
}
