<#
.SYNOPSIS
    WinPulse - Explainable Windows Service & Deep Startup Optimizer (WPF GUI)
.DESCRIPTION
    Scans Windows services and all startup vectors (Registry Run keys, Startup folders,
    and Logon/Boot Scheduled Tasks), maps each service to its actual PID to calculate
    real-time RAM usage (even inside shared svchost.exe processes), explains what each
    item does and what breaks if disabled, and creates automatic JSON state backups for
    1-click rollback.
#>

[CmdletBinding()]
param(
    [switch]$HeadlessScanOnly,
    [switch]$NoElevationPrompt
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# 1. Self-Elevation Check (skip when running HeadlessScanOnly in tests)
# ---------------------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $HeadlessScanOnly -and -not $NoElevationPrompt) {
    try {
        $scriptPath = $MyInvocation.MyCommand.Definition
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        exit
    } catch {
        Write-Warning "Running without Administrator privileges. Scanning works, but stopping system services requires Admin."
    }
}

# ---------------------------------------------------------------------------
# 2. Paths & Embedded Fallback Rules
# ---------------------------------------------------------------------------
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$RulesPath  = Join-Path $ScriptRoot "data\rules.json"
$BackupDir  = Join-Path $ScriptRoot "backups"
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

function Get-CuratedRules {
    if (Test-Path $RulesPath) {
        try {
            return (Get-Content -Path $RulesPath -Raw -Encoding UTF8 | ConvertFrom-Json)
        } catch {
            Write-Warning "Failed to parse rules.json: $_"
        }
    }
    throw "Could not find data\rules.json at $RulesPath"
}

# ---------------------------------------------------------------------------
# 3. Core Engine: Helpers & Service / Process RAM Scanner
# ---------------------------------------------------------------------------
function Get-ExecutableRamMB {
    param([string]$CommandText)
    if ([string]::IsNullOrWhiteSpace($CommandText)) { return 0.0 }

    $exeMatch = [regex]::Match($CommandText, '([a-zA-Z0-9_\-\.]+)\.exe', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $exeMatch.Success) { return 0.0 }

    $procName = $exeMatch.Groups[1].Value
    if ($procName -in @('cmd', 'powershell', 'pwsh', 'rundll32', 'regsvr32', 'wscript', 'cscript', 'explorer', 'svchost')) {
        return 0.0
    }

    $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if (-not $procs) { return 0.0 }

    $bytes = ($procs | Measure-Object -Property WorkingSet64 -Sum).Sum
    return [math]::Round(($bytes / 1MB), 1)
}

function Get-AnalyzedServices {
    $rules = Get-CuratedRules
    $ruleMap = @{}
    foreach ($s in $rules.services) {
        $ruleMap[$s.name.ToLower()] = $s
    }

    # Query Win32_Service for ProcessId, StartMode, State (with Get-Service & Registry fallback for restricted accounts)
    $cimServices = try { Get-CimInstance -ClassName Win32_Service -ErrorAction Stop } catch { $null }
    $cimMap = @{}
    $pidServiceCount = @{}

    if ($cimServices) {
        foreach ($cs in $cimServices) {
            $cimMap[$cs.Name.ToLower()] = $cs
            if ($cs.ProcessId -and $cs.ProcessId -gt 0) {
                if (-not $pidServiceCount.ContainsKey($cs.ProcessId)) {
                    $pidServiceCount[$cs.ProcessId] = 0
                }
                $pidServiceCount[$cs.ProcessId]++
            }
        }
    } else {
        # Fallback: Read service configuration directly from HKLM:\SYSTEM\CurrentControlSet\Services
        foreach ($rule in $rules.services) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($rule.name)"
            if (Test-Path $regPath) {
                $regSvc = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                $startCode = $regSvc.Start
                $startMode = switch ($startCode) {
                    2 { 'Auto' }
                    3 { 'Manual' }
                    4 { 'Disabled' }
                    default { 'Manual' }
                }
                $gs = Get-Service -Name $rule.name -ErrorAction SilentlyContinue
                $state = if ($gs) { [string]$gs.Status } elseif ($startCode -eq 2) { 'Running' } else { 'Stopped' }
                $cimMap[$rule.name.ToLower()] = [PSCustomObject]@{
                    Name      = $rule.name
                    State     = $state
                    StartMode = $startMode
                    ProcessId = 0
                    ImagePath = [string]$regSvc.ImagePath
                }
            }
        }
    }

    # Snapshot all running processes for fast WorkingSet64 lookup
    $procMap = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        $procMap[$p.Id] = $p
    }

    $results = New-Object System.Collections.Generic.List[PSObject]

    foreach ($rule in $rules.services) {
        $key = $rule.name.ToLower()
        if (-not $cimMap.ContainsKey($key)) { continue }

        $svc = $cimMap[$key]
        $pidVal = [int]$svc.ProcessId
        $ramMB = 0.0
        $sharedCount = 1

        if ($pidVal -gt 0 -and $procMap.ContainsKey($pidVal)) {
            $proc = $procMap[$pidVal]
            $sharedCount = if ($pidServiceCount[$pidVal] -gt 0) { $pidServiceCount[$pidVal] } else { 1 }
            # Apportion shared svchost RAM fairly across hosted services so totals never double-count
            $ramMB = [math]::Round(($proc.WorkingSet64 / 1MB) / $sharedCount, 2)
        } elseif ($svc.State -eq 'Running' -and $svc.PSObject.Properties['ImagePath']) {
            $ramMB = Get-ExecutableRamMB -CommandText $svc.ImagePath
        }

        $isRunning = ($svc.State -eq 'Running')
        $isSelected = ($isRunning -and [bool]$rule.recommendedByDefault)
        $isSafe = ($rule.tier -eq 'Safe')

        $results.Add([PSCustomObject]@{
            IsSelected    = [bool]$isSelected
            ServiceName   = $svc.Name
            DisplayName   = $rule.displayName
            State         = $svc.State
            StartMode     = $svc.StartMode
            PID           = if ($pidVal -gt 0) { "$pidVal" } else { "-" }
            RamMB         = [double]$ramMB
            RamDisplay    = if ($isRunning) { "{0:N1} MB" -f $ramMB } else { "Stopped" }
            Tier          = $rule.tier
            Category      = $rule.category
            Description   = $rule.description
            Impact        = $rule.impact
            Recommended   = [bool]$rule.recommendedByDefault
            # Visual color properties for clean status-free table
            StatusDot     = if ($isRunning) { "●" } else { "○" }
            StatusColor   = if ($isRunning) { "#10B981" } else { "#475569" }
            RowTextColor  = if ($isRunning) { "#F8FAFC" } else { "#64748B" }
            RamColor      = if ($isRunning -and $ramMB -gt 0) { "#38BDF8" } else { "#64748B" }
            TierColor     = if ($isSafe) { "#34D399" } else { "#FBBF24" }
            TierBgColor   = if ($isSafe) { "#064E3B" } else { "#451A03" }
        })
    }

    # Sort: Running services first by highest RAM usage, then stopped services
    return ($results | Sort-Object -Property @{Expression={$_.State -eq 'Running'}; Descending=$true}, @{Expression={$_.RamMB}; Descending=$true})
}

# ---------------------------------------------------------------------------
# 4. Core Engine: Deep Startup Scanner (Registry + Folders + Scheduled Tasks)
# ---------------------------------------------------------------------------
function Get-StartupClassification {
    param([string]$Name, [string]$Command, [object[]]$Patterns)
    $combined = "$Name $Command"
    foreach ($p in $Patterns) {
        if ($combined -match $p.pattern) {
            return [PSCustomObject]@{
                Tier        = $p.tier
                Reason      = $p.reason
                Recommended = [bool]$p.recommendedByDefault
            }
        }
    }
    return [PSCustomObject]@{
        Tier        = "Review"
        Reason      = "Third-party or custom startup entry running automatically on sign-in."
        Recommended = $false
    }
}

function Get-AnalyzedStartupItems {
    $rules = Get-CuratedRules
    $patterns = $rules.startupPatterns
    $items = New-Object System.Collections.Generic.List[PSObject]

    # A. Registry Run Keys
    $regLocations = @(
        @{ Scope = "HKCU Run"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ Scope = "HKLM Run"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ Scope = "HKLM WOW64 Run"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" }
    )
    if (Test-Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run") {
        $regLocations[2].Path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    } else {
        $regLocations = $regLocations[0..1]
    }

    foreach ($loc in $regLocations) {
        if (-not (Test-Path $loc.Path)) { continue }
        $props = Get-ItemProperty -Path $loc.Path -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
            $val = [string]$prop.Value
            # Skip Windows Security Health tray icon by default
            if ($prop.Name -match '^SecurityHealth$') { continue }

            $meta = Get-StartupClassification -Name $prop.Name -Command $val -Patterns $patterns
            $ram = Get-ExecutableRamMB -CommandText $val

            $items.Add([PSCustomObject]@{
                IsSelected  = [bool]$meta.Recommended
                Name        = $prop.Name
                SourceType  = "Registry ($($loc.Scope))"
                Location    = $loc.Path
                Command     = $val
                Status      = "Enabled"
                RamMB       = [double]$ram
                RamDisplay  = "{0:N1} MB" -f $ram
                Tier        = $meta.Tier
                Reason      = $meta.Reason
                Recommended = [bool]$meta.Recommended
            })
        }
    }

    # B. Startup Folders (User + Common)
    $folderLocations = @(
        @{ Scope = "User Startup Folder"; Path = [Environment]::GetFolderPath('Startup') },
        @{ Scope = "Common Startup Folder"; Path = [Environment]::GetFolderPath('CommonStartup') }
    )
    foreach ($floc in $folderLocations) {
        if (-not $floc.Path -or -not (Test-Path $floc.Path)) { continue }
        $files = Get-ChildItem -Path $floc.Path -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' }
        foreach ($f in $files) {
            $meta = Get-StartupClassification -Name $f.BaseName -Command $f.FullName -Patterns $patterns
            $ram = Get-ExecutableRamMB -CommandText $f.Name

            $items.Add([PSCustomObject]@{
                IsSelected  = [bool]$meta.Recommended
                Name        = $f.BaseName
                SourceType  = $floc.Scope
                Location    = $f.FullName
                Command     = $f.FullName
                Status      = "Enabled"
                RamMB       = [double]$ram
                RamDisplay  = "{0:N1} MB" -f $ram
                Tier        = $meta.Tier
                Reason      = $meta.Reason
                Recommended = [bool]$meta.Recommended
            })
        }
    }

    # C. Non-Microsoft Scheduled Tasks that trigger at Logon or Boot (Hidden from Task Manager!)
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.State -ne 'Disabled' -and $_.TaskPath -notmatch '^\\Microsoft\\Windows\\'
        }
        foreach ($t in $tasks) {
            $actionExec = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; '
            if ([string]::IsNullOrWhiteSpace($actionExec)) { continue }

            $meta = Get-StartupClassification -Name $t.TaskName -Command $actionExec -Patterns $patterns
            $ram = Get-ExecutableRamMB -CommandText $actionExec

            $items.Add([PSCustomObject]@{
                IsSelected  = [bool]$meta.Recommended
                Name        = $t.TaskName
                SourceType  = "Scheduled Task (Hidden in TaskMgr)"
                Location    = "$($t.TaskPath)$($t.TaskName)"
                TaskPath    = $t.TaskPath
                TaskName    = $t.TaskName
                Command     = $actionExec
                Status      = [string]$t.State
                RamMB       = [double]$ram
                RamDisplay  = "{0:N1} MB" -f $ram
                Tier        = $meta.Tier
                Reason      = $meta.Reason
                Recommended = [bool]$meta.Recommended
            })
        }
    } catch {
        # Fallback: Read third-party scheduled tasks directly from C:\Windows\System32\Tasks if WMI is restricted
        $tasksRoot = Join-Path $env:SystemRoot "System32\Tasks"
        if (Test-Path $tasksRoot) {
            $taskFiles = Get-ChildItem -Path $tasksRoot -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $_.FullName -notlike "*\Microsoft\Windows\*"
            }
            foreach ($tf in $taskFiles) {
                $relPath = $tf.FullName.Substring($tasksRoot.Length)
                $taskFolder = Split-Path $relPath -Parent
                if (-not $taskFolder.EndsWith("\")) { $taskFolder += "\" }
                $meta = Get-StartupClassification -Name $tf.Name -Command $relPath -Patterns $patterns
                $ram = Get-ExecutableRamMB -CommandText $tf.Name

                $items.Add([PSCustomObject]@{
                    IsSelected  = [bool]$meta.Recommended
                    Name        = $tf.Name
                    SourceType  = "Scheduled Task (Hidden in TaskMgr)"
                    Location    = $relPath
                    TaskPath    = $taskFolder
                    TaskName    = $tf.Name
                    Command     = $relPath
                    Status      = "Ready"
                    RamMB       = [double]$ram
                    RamDisplay  = "{0:N1} MB" -f $ram
                    Tier        = $meta.Tier
                    Reason      = $meta.Reason
                    Recommended = [bool]$meta.Recommended
                })
            }
        }
    }

    return ($items | Sort-Object -Property @{Expression={$_.Recommended}; Descending=$true}, @{Expression={$_.RamMB}; Descending=$true})
}

# ---------------------------------------------------------------------------
# 5. Headless Verification Mode (for Automated Testing / CLI summary)
# ---------------------------------------------------------------------------
if ($HeadlessScanOnly) {
    $svcs = Get-AnalyzedServices
    $startups = Get-AnalyzedStartupItems
    $runningSvcs = $svcs | Where-Object { $_.State -eq 'Running' }
    $totalSvcRam = ($runningSvcs | Measure-Object -Property RamMB -Sum).Sum
    $totalStartupRam = ($startups | Measure-Object -Property RamMB -Sum).Sum

    [PSCustomObject]@{
        MatchedServicesCount = $svcs.Count
        RunningServicesCount = $runningSvcs.Count
        ServiceRamMB         = [math]::Round($totalSvcRam, 2)
        StartupItemsCount    = $startups.Count
        StartupRamMB         = [math]::Round($totalStartupRam, 2)
    } | ConvertTo-Json
    exit 0
}

# ---------------------------------------------------------------------------
# 6. Action & Backup/Rollback Engine
# ---------------------------------------------------------------------------
function Optimize-SelectedItems {
    param(
        [object[]]$SelectedServices,
        [object[]]$SelectedStartups
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $BackupDir "backup_$timestamp.json"

    $backupPayload = @{
        Timestamp = (Get-Date).ToString("o")
        Services  = @()
        Startups  = @()
    }

    $logMessages = New-Object System.Collections.Generic.List[string]
    $freedRamMB = 0.0

    # 1. Process Services
    foreach ($svc in $SelectedServices) {
        $backupPayload.Services += @{
            ServiceName = $svc.ServiceName
            DisplayName = $svc.DisplayName
            StartMode   = if ($svc.StartMode -eq 'Auto') { 'Automatic' } elseif ($svc.StartMode -eq 'Manual') { 'Manual' } else { 'Automatic' }
            WasRunning  = ($svc.State -eq 'Running')
        }

        try {
            if ($svc.State -eq 'Running') {
                Stop-Service -Name $svc.ServiceName -Force -ErrorAction Stop
            }
            Set-Service -Name $svc.ServiceName -StartupType Disabled -ErrorAction Stop
            $freedRamMB += $svc.RamMB
            $logMessages.Add("[OK] Stopped & Disabled service: $($svc.DisplayName) ($($svc.ServiceName)) - Freed $($svc.RamDisplay)")
        } catch {
            $logMessages.Add("[WARN] Could not modify service $($svc.ServiceName): $($_.Exception.Message)")
        }
    }

    # 2. Process Startup Items
    foreach ($st in $SelectedStartups) {
        if ($st.SourceType -like "Registry*") {
            $backupPayload.Startups += @{
                Type     = "Registry"
                Name     = $st.Name
                Location = $st.Location
                Command  = $st.Command
            }
            try {
                Remove-ItemProperty -Path $st.Location -Name $st.Name -Force -ErrorAction Stop
                $freedRamMB += $st.RamMB
                $logMessages.Add("[OK] Removed Registry startup: $($st.Name) from $($st.Location)")
            } catch {
                $logMessages.Add("[WARN] Failed to remove Registry startup $($st.Name): $($_.Exception.Message)")
            }
        }
        elseif ($st.SourceType -like "*Startup Folder*") {
            $disabledDir = Join-Path (Split-Path $st.Location -Parent) "WinPulse_Disabled"
            if (-not (Test-Path $disabledDir)) {
                New-Item -ItemType Directory -Path $disabledDir -Force | Out-Null
            }
            $targetPath = Join-Path $disabledDir (Split-Path $st.Location -Leaf)
            $backupPayload.Startups += @{
                Type         = "Folder"
                Name         = $st.Name
                OriginalPath = $st.Location
                DisabledPath = $targetPath
            }
            try {
                Move-Item -Path $st.Location -Destination $targetPath -Force -ErrorAction Stop
                $freedRamMB += $st.RamMB
                $logMessages.Add("[OK] Moved startup shortcut $($st.Name) to backup folder")
            } catch {
                $logMessages.Add("[WARN] Failed to move shortcut $($st.Name): $($_.Exception.Message)")
            }
        }
        elseif ($st.SourceType -like "Scheduled Task*") {
            $backupPayload.Startups += @{
                Type     = "ScheduledTask"
                Name     = $st.Name
                TaskPath = $st.TaskPath
                TaskName = $st.TaskName
            }
            try {
                Disable-ScheduledTask -TaskPath $st.TaskPath -TaskName $st.TaskName -ErrorAction Stop | Out-Null
                $freedRamMB += $st.RamMB
                $logMessages.Add("[OK] Disabled hidden Startup Scheduled Task: $($st.Name)")
            } catch {
                $logMessages.Add("[WARN] Failed to disable Scheduled Task $($st.Name): $($_.Exception.Message)")
            }
        }
    }

    # Save backup snapshot if anything was attempted
    if (($backupPayload.Services.Count + $backupPayload.Startups.Count) -gt 0) {
        $backupPayload | ConvertTo-Json -Depth 6 | Set-Content -Path $backupFile -Encoding UTF8
        $logMessages.Insert(0, "[BACKUP] Saved state snapshot to: $backupFile")
    }

    return [PSCustomObject]@{
        BackupFile = $backupFile
        FreedRamMB = [math]::Round($freedRamMB, 1)
        Logs       = ($logMessages -join "`r`n")
    }
}

function Restore-BackupSnapshot {
    param([string]$BackupFilePath)
    if (-not (Test-Path $BackupFilePath)) {
        return "Backup file not found: $BackupFilePath"
    }

    $data = Get-Content -Path $BackupFilePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $logs = New-Object System.Collections.Generic.List[string]
    $logs.Add("[RESTORE] Restoring snapshot from $($data.Timestamp)...")

    foreach ($s in $data.Services) {
        try {
            $mode = if ($s.StartMode -in @('Automatic','Manual','Disabled')) { $s.StartMode } else { 'Manual' }
            Set-Service -Name $s.ServiceName -StartupType $mode -ErrorAction Stop
            if ($s.WasRunning) {
                Start-Service -Name $s.ServiceName -ErrorAction SilentlyContinue
            }
            $logs.Add("[OK] Restored service $($s.DisplayName) ($($s.ServiceName)) to $mode")
        } catch {
            $logs.Add("[WARN] Could not restore service $($s.ServiceName): $($_.Exception.Message)")
        }
    }

    foreach ($st in $data.Startups) {
        try {
            if ($st.Type -eq "Registry") {
                Set-ItemProperty -Path $st.Location -Name $st.Name -Value $st.Command -ErrorAction Stop
                $logs.Add("[OK] Restored Registry startup: $($st.Name)")
            }
            elseif ($st.Type -eq "Folder") {
                if (Test-Path $st.DisabledPath) {
                    Move-Item -Path $st.DisabledPath -Destination $st.OriginalPath -Force -ErrorAction Stop
                    $logs.Add("[OK] Restored startup shortcut: $($st.Name)")
                }
            }
            elseif ($st.Type -eq "ScheduledTask") {
                Enable-ScheduledTask -TaskPath $st.TaskPath -TaskName $st.TaskName -ErrorAction Stop | Out-Null
                $logs.Add("[OK] Re-enabled Scheduled Task: $($st.Name)")
            }
        } catch {
            $logs.Add("[WARN] Could not restore startup item $($st.Name): $($_.Exception.Message)")
        }
    }

    return ($logs -join "`r`n")
}

# ---------------------------------------------------------------------------
# 7. WPF GUI Presentation Layer
# ---------------------------------------------------------------------------
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="WinPulse - Explainable Windows Service &amp; Deep Startup Optimizer"
        Height="780" Width="1220" MinHeight="640" MinWidth="980"
        WindowStartupLocation="CenterScreen"
        Background="#0F172A" Foreground="#F8FAFC"
        FontFamily="Segoe UI">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#1E293B"/>
            <Setter Property="Foreground" Value="#F8FAFC"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="14,8"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
        <Style TargetType="DataGrid">
            <Setter Property="Background" Value="#0F172A"/>
            <Setter Property="Foreground" Value="#F1F5F9"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="RowBackground" Value="#1E293B"/>
            <Setter Property="AlternatingRowBackground" Value="#162032"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="HorizontalGridLinesBrush" Value="#334155"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="SelectionMode" Value="Single"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="#020617"/>
            <Setter Property="Foreground" Value="#94A3B8"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="BorderBrush" Value="#334155"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>
    </Window.Resources>

    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header & Dashboard Metrics -->
        <Grid Grid.Row="0" Margin="0,0,0,14">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <StackPanel Grid.Column="0">
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="WinPulse" FontSize="26" FontWeight="Bold" Foreground="#38BDF8"/>
                    <Border Background="#1E293B" CornerRadius="6" Padding="8,3" Margin="12,0,0,0" VerticalAlignment="Center" BorderBrush="#334155" BorderThickness="1">
                        <TextBlock Name="TxtAdminBadge" Text="Checking Privileges..." FontSize="12" FontWeight="SemiBold" Foreground="#34D399"/>
                    </Border>
                </StackPanel>
                <TextBlock Text="See exact per-service memory usage, understand what breaks before disabling, and clean hidden startup tasks Task Manager misses."
                           Foreground="#94A3B8" FontSize="13" Margin="0,4,0,0"/>
            </StackPanel>

            <!-- Live Metric Cards -->
            <StackPanel Grid.Column="1" Orientation="Horizontal">
                <Border Background="#1E293B" BorderBrush="#334155" BorderThickness="1" CornerRadius="8" Padding="14,8" Margin="0,0,10,0">
                    <StackPanel>
                        <TextBlock Text="UNNECESSARY RUNNING SERVICES" Foreground="#94A3B8" FontSize="10" FontWeight="Bold"/>
                        <TextBlock Name="TxtRunningCount" Text="0" Foreground="#38BDF8" FontSize="20" FontWeight="Bold"/>
                    </StackPanel>
                </Border>
                <Border Background="#1E293B" BorderBrush="#334155" BorderThickness="1" CornerRadius="8" Padding="14,8" Margin="0,0,10,0">
                    <StackPanel>
                        <TextBlock Text="STARTUP &amp; HIDDEN TASKS" Foreground="#94A3B8" FontSize="10" FontWeight="Bold"/>
                        <TextBlock Name="TxtStartupCount" Text="0" Foreground="#A78BFA" FontSize="20" FontWeight="Bold"/>
                    </StackPanel>
                </Border>
                <Border Background="#064E3B" BorderBrush="#059669" BorderThickness="1" CornerRadius="8" Padding="16,8">
                    <StackPanel>
                        <TextBlock Text="SELECTED RAM TO RECLAIM" Foreground="#A7F3D0" FontSize="10" FontWeight="Bold"/>
                        <TextBlock Name="TxtReclaimRam" Text="0.0 MB" Foreground="#34D399" FontSize="20" FontWeight="Bold"/>
                    </StackPanel>
                </Border>
            </StackPanel>
        </Grid>

        <!-- Action Preset Toolbar -->
        <Border Grid.Row="1" Background="#1E293B" BorderBrush="#334155" BorderThickness="1" CornerRadius="8" Padding="10" Margin="0,0,0,12">
            <DockPanel>
                <StackPanel Orientation="Horizontal" DockPanel.Dock="Left">
                    <Button Name="BtnSelectSafe" Content="Select Safe Recommended Only" Margin="0,0,8,0" Background="#0284C7" BorderBrush="#38BDF8"/>
                    <Button Name="BtnSelectAllRunning" Content="Select All Running Bloat" Margin="0,0,8,0"/>
                    <Button Name="BtnClearAll" Content="Uncheck All" Margin="0,0,8,0"/>
                    <Button Name="BtnRescan" Content="Refresh Live RAM Scan"/>
                </StackPanel>
                <StackPanel Orientation="Horizontal" DockPanel.Dock="Right" HorizontalAlignment="Right">
                    <Button Name="BtnRestore" Content="1-Click Undo / Restore Backup" Margin="0,0,10,0" Background="#334155"/>
                    <Button Name="BtnOptimize" Content="Stop &amp; Disable Selected Items" Background="#059669" BorderBrush="#10B981" Padding="18,8" FontSize="13.5"/>
                </StackPanel>
            </DockPanel>
        </Border>

        <!-- Main Tab Control -->
        <TabControl Grid.Row="2" Background="#0F172A" BorderBrush="#334155">
            <!-- TAB 1: Windows Services -->
            <TabItem Header="  Windows Services (Live RAM &amp; Impact)  " FontSize="14" FontWeight="SemiBold">
                <Grid Margin="6">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <!-- Color Legend Bar -->
                    <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="4,2,0,8">
                        <TextBlock Text="● Running Service (Active in RAM)" Foreground="#10B981" FontWeight="SemiBold" FontSize="12" Margin="0,0,20,0"/>
                        <TextBlock Text="○ Stopped / Disabled Service" Foreground="#64748B" FontWeight="SemiBold" FontSize="12" Margin="0,0,20,0"/>
                        <TextBlock Text="■ Safe (Telemetry &amp; Unused Bloat)" Foreground="#34D399" FontWeight="SemiBold" FontSize="12" Margin="0,0,20,0"/>
                        <TextBlock Text="■ Optional (Feature-Specific)" Foreground="#FBBF24" FontWeight="SemiBold" FontSize="12"/>
                    </StackPanel>

                    <DataGrid Name="GridServices" Grid.Row="1" RowHeight="36">
                        <DataGrid.Columns>
                            <DataGridCheckBoxColumn Header="Disable" Binding="{Binding IsSelected, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" Width="68"/>

                            <!-- Color-Coded Service Name (Green dot = Running, Dimmed gray = Stopped) -->
                            <DataGridTemplateColumn Header="Service Name" Width="290" IsReadOnly="True">
                                <DataGridTemplateColumn.CellTemplate>
                                    <DataTemplate>
                                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="8,0">
                                            <TextBlock Text="{Binding StatusDot}" Foreground="{Binding StatusColor}" FontSize="14" FontWeight="Bold" Margin="0,0,8,0" VerticalAlignment="Center"/>
                                            <TextBlock Text="{Binding DisplayName}" Foreground="{Binding RowTextColor}" FontWeight="SemiBold" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
                                        </StackPanel>
                                    </DataTemplate>
                                </DataGridTemplateColumn.CellTemplate>
                            </DataGridTemplateColumn>

                            <!-- Live RAM Footprint -->
                            <DataGridTemplateColumn Header="RAM Used" Width="105" IsReadOnly="True">
                                <DataGridTemplateColumn.CellTemplate>
                                    <DataTemplate>
                                        <TextBlock Text="{Binding RamDisplay}" Foreground="{Binding RamColor}" FontWeight="Bold" VerticalAlignment="Center" Margin="10,0"/>
                                    </DataTemplate>
                                </DataGridTemplateColumn.CellTemplate>
                            </DataGridTemplateColumn>

                            <!-- Color-Coded Safety Badge -->
                            <DataGridTemplateColumn Header="Safety" Width="95" IsReadOnly="True">
                                <DataGridTemplateColumn.CellTemplate>
                                    <DataTemplate>
                                        <Border Background="{Binding TierBgColor}" CornerRadius="4" Padding="8,2" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="8,0">
                                            <TextBlock Text="{Binding Tier}" Foreground="{Binding TierColor}" FontWeight="Bold" FontSize="11.5"/>
                                        </Border>
                                    </DataTemplate>
                                </DataGridTemplateColumn.CellTemplate>
                            </DataGridTemplateColumn>

                            <!-- What Breaks If Disabled? -->
                            <DataGridTemplateColumn Header="What Breaks If Disabled?" Width="*" IsReadOnly="True">
                                <DataGridTemplateColumn.CellTemplate>
                                    <DataTemplate>
                                        <TextBlock Text="{Binding Impact}" Foreground="{Binding RowTextColor}" VerticalAlignment="Center" Margin="10,0" TextTrimming="CharacterEllipsis"/>
                                    </DataTemplate>
                                </DataGridTemplateColumn.CellTemplate>
                            </DataGridTemplateColumn>
                        </DataGrid.Columns>
                    </DataGrid>

                    <!-- Service Details Inspector Card -->
                    <Border Grid.Row="2" Background="#1E293B" BorderBrush="#334155" BorderThickness="1" CornerRadius="6" Padding="12" Margin="0,8,0,0">
                        <StackPanel>
                            <TextBlock Name="TxtSvcInspectorTitle" Text="Click any service row above to inspect full details and side-effects." FontWeight="Bold" Foreground="#38BDF8" FontSize="13.5"/>
                            <TextBlock Name="TxtSvcInspectorDesc" Text="WinPulse resolves shared svchost.exe PIDs via WMI/CIM so you can see the actual memory footprint of background services." Foreground="#CBD5E1" Margin="0,4,0,0" TextWrapping="Wrap"/>
                            <TextBlock Name="TxtSvcInspectorImpact" Text="" Foreground="#FBBF24" Margin="0,4,0,0" FontWeight="SemiBold" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>
                </Grid>
            </TabItem>

            <!-- TAB 2: Deep Startup & Hidden Scheduled Tasks -->
            <TabItem Header="  Deep Startup &amp; Scheduled Tasks  " FontSize="14" FontWeight="SemiBold">
                <Grid Margin="6">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <DataGrid Name="GridStartup" Grid.Row="0" RowHeight="36">
                        <DataGrid.Columns>
                            <DataGridCheckBoxColumn Header="Remove" Binding="{Binding IsSelected, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" Width="68"/>
                            <DataGridTextColumn Header="Startup App / Task" Binding="{Binding Name}" Width="240" IsReadOnly="True" FontWeight="SemiBold"/>
                            <DataGridTextColumn Header="Active RAM" Binding="{Binding RamDisplay}" Width="105" IsReadOnly="True" FontWeight="Bold"/>
                            <DataGridTextColumn Header="Safety" Binding="{Binding Tier}" Width="85" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Where It Hides" Binding="{Binding SourceType}" Width="230" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Why Disable / What Breaks?" Binding="{Binding Reason}" Width="*" IsReadOnly="True"/>
                        </DataGrid.Columns>
                    </DataGrid>

                    <Border Grid.Row="1" Background="#1E293B" BorderBrush="#334155" BorderThickness="1" CornerRadius="6" Padding="12" Margin="0,8,0,0">
                        <TextBlock Name="TxtStartupInspector" Text="Note: Unlike Windows Task Manager (which only shows Registry Run keys and Startup folders), this scanner also exposes third-party Logon &amp; Boot Scheduled Tasks (where Adobe, Google, Edge, and updaters hide)."
                                   Foreground="#CBD5E1" TextWrapping="Wrap"/>
                    </Border>
                </Grid>
            </TabItem>

            <!-- TAB 3: Why Not Just Task Manager? -->
            <TabItem Header="  Why Not Task Manager? &amp; Activity Log  " FontSize="14" FontWeight="SemiBold">
                <Grid Margin="10">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>

                    <Border Grid.Column="0" Background="#1E293B" BorderBrush="#334155" BorderThickness="1" CornerRadius="8" Padding="16" Margin="0,0,8,0">
                        <StackPanel>
                            <TextBlock Text="Why Task Manager isn't enough:" FontSize="17" FontWeight="Bold" Foreground="#38BDF8" Margin="0,0,0,10"/>
                            <TextBlock TextWrapping="Wrap" Foreground="#E2E8F0" Margin="0,0,0,8">
                                1. Hides Per-Service RAM: Task Manager's Services tab shows 0 memory data, and the Processes tab lumps dozens of services into generic 'Service Host (svchost.exe)' buckets. WinPulse maps each service to its exact PID and calculates its memory share.
                            </TextBlock>
                            <TextBlock TextWrapping="Wrap" Foreground="#E2E8F0" Margin="0,0,0,8">
                                2. No 'What Breaks?' Guidance: Task Manager lists 250+ cryptic names like 'DiagTrack', 'SysMain', or 'PcaSvc' without telling you which ones are telemetry bloat versus critical OS components.
                            </TextBlock>
                            <TextBlock TextWrapping="Wrap" Foreground="#E2E8F0" Margin="0,0,0,8">
                                3. Services Restart After Reboot: Stopping a service in Task Manager only stops it for the current session. WinPulse both stops the running service AND sets its startup mode to Disabled.
                            </TextBlock>
                            <TextBlock TextWrapping="Wrap" Foreground="#E2E8F0" Margin="0,0,0,8">
                                4. Misses Scheduled Task Startups: Task Manager's Startup Apps tab ignores Windows Task Scheduler, where Chrome, Edge, Adobe, and OEM bloatware register logon triggers.
                            </TextBlock>
                            <TextBlock TextWrapping="Wrap" Foreground="#E2E8F0">
                                5. Automatic 1-Click Rollback: Every time you optimize, WinPulse writes a timestamped JSON snapshot in /backups so you can undo changes in one click.
                            </TextBlock>
                        </StackPanel>
                    </Border>

                    <Border Grid.Column="1" Background="#020617" BorderBrush="#334155" BorderThickness="1" CornerRadius="8" Padding="14" Margin="8,0,0,0">
                        <DockPanel>
                            <TextBlock DockPanel.Dock="Top" Text="Session Activity &amp; Rollback Log" FontSize="15" FontWeight="Bold" Foreground="#34D399" Margin="0,0,0,8"/>
                            <TextBox Name="TxtActivityLog" Background="#020617" Foreground="#A7F3D0" BorderThickness="0"
                                     FontFamily="Consolas" FontSize="12.5" IsReadOnly="True" TextWrapping="Wrap"
                                     VerticalScrollBarVisibility="Auto" AcceptsReturn="True"
                                     Text="Ready. Select items and click 'Stop &amp; Disable Selected Items' to reclaim memory."/>
                        </DockPanel>
                    </Border>
                </Grid>
            </TabItem>
        </TabControl>

        <!-- Footer Status Bar -->
        <DockPanel Grid.Row="3" Margin="0,10,0,0">
            <TextBlock Name="TxtFooterStatus" Text="Scan complete." Foreground="#94A3B8" FontSize="12"/>
            <TextBlock Text="Backups stored automatically in ./backups/*.json" Foreground="#64748B" FontSize="12" HorizontalAlignment="Right"/>
        </DockPanel>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Bind UI controls
$TxtAdminBadge        = $window.FindName("TxtAdminBadge")
$TxtRunningCount      = $window.FindName("TxtRunningCount")
$TxtStartupCount      = $window.FindName("TxtStartupCount")
$TxtReclaimRam        = $window.FindName("TxtReclaimRam")
$GridServices         = $window.FindName("GridServices")
$GridStartup          = $window.FindName("GridStartup")
$TxtSvcInspectorTitle = $window.FindName("TxtSvcInspectorTitle")
$TxtSvcInspectorDesc  = $window.FindName("TxtSvcInspectorDesc")
$TxtSvcInspectorImpact= $window.FindName("TxtSvcInspectorImpact")
$TxtStartupInspector  = $window.FindName("TxtStartupInspector")
$TxtActivityLog       = $window.FindName("TxtActivityLog")
$TxtFooterStatus      = $window.FindName("TxtFooterStatus")

$BtnSelectSafe        = $window.FindName("BtnSelectSafe")
$BtnSelectAllRunning  = $window.FindName("BtnSelectAllRunning")
$BtnClearAll          = $window.FindName("BtnClearAll")
$BtnRescan            = $window.FindName("BtnRescan")
$BtnRestore           = $window.FindName("BtnRestore")
$BtnOptimize          = $window.FindName("BtnOptimize")

if ($isAdmin) {
    $TxtAdminBadge.Text = "Administrator Mode (Full Control)"
    $TxtAdminBadge.Foreground = "#34D399"
} else {
    $TxtAdminBadge.Text = "Standard User (Run as Admin to Stop Services)"
    $TxtAdminBadge.Foreground = "#FBBF24"
}

$script:ServiceList = New-Object System.Collections.ObjectModel.ObservableCollection[PSObject]
$script:StartupList = New-Object System.Collections.ObjectModel.ObservableCollection[PSObject]

function Update-DashboardCounters {
    $runningCurated = @($script:ServiceList | Where-Object { $_.State -eq 'Running' })
    $TxtRunningCount.Text = "$($runningCurated.Count) / $($script:ServiceList.Count)"
    $TxtStartupCount.Text = "$($script:StartupList.Count)"

    $selectedSvcRam = ($script:ServiceList | Where-Object { $_.IsSelected -and $_.State -eq 'Running' } | Measure-Object -Property RamMB -Sum).Sum
    $selectedStRam  = ($script:StartupList | Where-Object { $_.IsSelected } | Measure-Object -Property RamMB -Sum).Sum
    $totalReclaim   = [math]::Round(($selectedSvcRam + $selectedStRam), 1)
    $selectedCount  = @($script:ServiceList | Where-Object { $_.IsSelected }).Count + @($script:StartupList | Where-Object { $_.IsSelected }).Count

    $TxtReclaimRam.Text = "{0:N1} MB ({1} items)" -f $totalReclaim, $selectedCount
}

function Invoke-SystemScan {
    $TxtFooterStatus.Text = "Scanning live Windows services, svchost PIDs, Registry Run keys, and Scheduled Tasks..."
    $script:ServiceList.Clear()
    $script:StartupList.Clear()

    foreach ($s in (Get-AnalyzedServices)) {
        $script:ServiceList.Add($s)
    }
    foreach ($st in (Get-AnalyzedStartupItems)) {
        $script:StartupList.Add($st)
    }

    $GridServices.ItemsSource = $script:ServiceList
    $GridStartup.ItemsSource  = $script:StartupList
    Update-DashboardCounters
    $TxtFooterStatus.Text = "Live scan complete at $(Get-Date -Format 'HH:mm:ss'). Checked items default to 'Safe' telemetry & bloatware."
}

# Inspector update on row click (shows full description + technical metadata only on demand)
$GridServices.Add_SelectionChanged({
    $sel = $GridServices.SelectedItem
    if ($null -ne $sel) {
        $TxtSvcInspectorTitle.Text  = "$($sel.DisplayName)  •  [$($sel.State) | $($sel.RamDisplay) | Service ID: $($sel.ServiceName) | PID: $($sel.PID) | Category: $($sel.Category)]"
        $TxtSvcInspectorDesc.Text   = "What it does: $($sel.Description)"
        $TxtSvcInspectorImpact.Text = "What breaks if disabled: $($sel.Impact)"
    }
})

$GridStartup.Add_SelectionChanged({
    $sel = $GridStartup.SelectedItem
    if ($null -ne $sel) {
        $TxtStartupInspector.Text = "$($sel.Name) ($($sel.SourceType)) — Command/Path: $($sel.Command)"
    }
})

# Recalculate RAM counter when checkboxes change
$GridServices.Add_CurrentCellChanged({ Update-DashboardCounters })
$GridStartup.Add_CurrentCellChanged({ Update-DashboardCounters })

$BtnSelectSafe.Add_Click({
    foreach ($s in $script:ServiceList) {
        $s.IsSelected = ($s.State -eq 'Running' -and $s.Tier -eq 'Safe')
    }
    foreach ($st in $script:StartupList) {
        $st.IsSelected = ($st.Tier -eq 'Safe')
    }
    $GridServices.Items.Refresh()
    $GridStartup.Items.Refresh()
    Update-DashboardCounters
})

$BtnSelectAllRunning.Add_Click({
    foreach ($s in $script:ServiceList) {
        $s.IsSelected = ($s.State -eq 'Running')
    }
    foreach ($st in $script:StartupList) {
        $st.IsSelected = ($st.Tier -in @('Safe', 'Optional'))
    }
    $GridServices.Items.Refresh()
    $GridStartup.Items.Refresh()
    Update-DashboardCounters
})

$BtnClearAll.Add_Click({
    foreach ($s in $script:ServiceList) { $s.IsSelected = $false }
    foreach ($st in $script:StartupList) { $st.IsSelected = $false }
    $GridServices.Items.Refresh()
    $GridStartup.Items.Refresh()
    Update-DashboardCounters
})

$BtnRescan.Add_Click({ Invoke-SystemScan })

$BtnOptimize.Add_Click({
    $selSvcs = @($script:ServiceList | Where-Object { $_.IsSelected })
    $selSts  = @($script:StartupList | Where-Object { $_.IsSelected })
    $totalSel = $selSvcs.Count + $selSts.Count

    if ($totalSel -eq 0) {
        [System.Windows.MessageBox]::Show("No services or startup items are checked.", "WinPulse", "OK", "Information") | Out-Null
        return
    }

    $confirmMsg = "You are about to stop & disable $($selSvcs.Count) service(s) and remove/disable $($selSts.Count) startup item(s).`r`n`r`nAn automatic rollback backup will be saved in ./backups first.`r`nProceed?"
    $ans = [System.Windows.MessageBox]::Show($confirmMsg, "Confirm Optimization", "YesNo", "Question")
    if ($ans -ne "Yes") { return }

    $res = Optimize-SelectedItems -SelectedServices $selSvcs -SelectedStartups $selSts
    $TxtActivityLog.Text = $res.Logs + "`r`n`r`n" + $TxtActivityLog.Text
    Invoke-SystemScan
    [System.Windows.MessageBox]::Show("Optimization complete!`r`nReclaimed approximately $($res.FreedRamMB) MB of live RAM.`r`n`r`nBackup saved to:`r`n$($res.BackupFile)", "WinPulse Complete", "OK", "Information") | Out-Null
})

$BtnRestore.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.InitialDirectory = $BackupDir
    $dlg.Filter = "WinPulse Backup JSON (*.json)|*.json"
    $dlg.Title = "Select a WinPulse Backup Snapshot to Restore"

    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $log = Restore-BackupSnapshot -BackupFilePath $dlg.FileName
        $TxtActivityLog.Text = $log + "`r`n`r`n" + $TxtActivityLog.Text
        Invoke-SystemScan
        [System.Windows.MessageBox]::Show("Backup snapshot restored! Details written to the Activity Log tab.", "Restore Complete", "OK", "Information") | Out-Null
    }
})

# Initial scan on startup
Invoke-SystemScan

$window.ShowDialog() | Out-Null
