function Write-Section {
    param ($title)
    Write-Host "`n=== $title ===" -ForegroundColor Cyan
}

function Write-Item {
    param ($label, $value)
    Write-Host ("{0,-22} {1}" -f $label, $value) -ForegroundColor Gray
}

function Write-CategoryHeader {
    param ($label)
    Write-Host "`n--- $label ---" -ForegroundColor Magenta
}

function Show-Menu {
    Write-Host "`nSystem Scanning Toolkit" -ForegroundColor Magenta
    Write-Host "------------------------" -ForegroundColor Magenta
    Write-Host "Select an option:`n" -ForegroundColor White
    Write-Host "[1] System and networking information" -ForegroundColor Green
    Write-Host "[2] Software Bill of Materials (SBOM)" -ForegroundColor Blue
    Write-Host "[0] Exit`n" -ForegroundColor DarkRed
}

function Run-AdminCheck {
    Write-Section "PRIVILEGE CHECK"
    $script:isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($isAdmin) {
        Write-Host "User has administrative privileges. Running full scan..." -ForegroundColor Green
    } else {
        Write-Host "User does NOT have administrative privileges." -ForegroundColor DarkYellow
        Write-Host "Output will be limited. For full results, re-run this script as Administrator." -ForegroundColor DarkYellow
    }
}

function Ensure-ExportFolder {
    if (-not $script:exportFolder) {
        $stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $script:exportFolder = "SST_Files_$stamp"
        New-Item -ItemType Directory -Path $exportFolder -Force | Out-Null
    }
}

function Run-SystemScan {
    $sysInfo = Get-ComputerInfo
    $output = @()

    Write-Section "SYSTEM INFORMATION"
    $sysSection = @(
        "Host Name:          $env:COMPUTERNAME",
        "OS Name:            $($sysInfo.OsName)",
        "OS Version:         $($sysInfo.OsDisplayVersion)",
        "Build Number:       $($sysInfo.OsBuildNumber)",
        "Architecture:       $($sysInfo.OsArchitecture)",
        "OS Configuration:   $($sysInfo.OsConfiguration)",
        "System Type:        $($sysInfo.SystemType)"
    )
    $sysSection | ForEach-Object {
        Write-Host $_ -ForegroundColor Gray
        $output += $_
    }

    Write-Section "REGISTRATION & HARDWARE"
    $hwSection = @(
        "Registered Owner:   $($sysInfo.OsRegisteredUser)",
        "Registered Org:     $($sysInfo.OsRegisteredOrganization)",
        "Product ID:         $($sysInfo.WindowsProductId)",
        "Manufacturer:       $($sysInfo.CsManufacturer)",
        "Model:              $($sysInfo.CsModel)"
    )
    $hwSection | ForEach-Object {
        Write-Host $_ -ForegroundColor Gray
        $output += $_
    }

    Write-Section "RECENT HOTFIXES (max 10)"
    $output += "`n=== RECENT HOTFIXES ==="
    if ($isAdmin) {
        try {
            $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
            $hotfixes | Format-Table -AutoSize
            $output += $hotfixes | ForEach-Object { "$($_.HotFixID) - $($_.InstalledOn)" }
        } catch {
            Write-Host "Warning: Failed to retrieve hotfixes." -ForegroundColor DarkRed
            $output += "Warning: Failed to retrieve hotfixes."
        }
    } else {
        Write-Host "Skipped: Requires admin privileges to retrieve hotfixes." -ForegroundColor DarkYellow
        $output += "Skipped: Requires admin privileges to retrieve hotfixes."
    }

    Write-Section "NETWORK ADAPTER(S)"
    $output += "`n=== NETWORK ADAPTERS ==="
    $netConfigs = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }
    foreach ($adapter in $netConfigs) {
        $output += "`nAdapter:           $($adapter.InterfaceAlias)"
        $output += "IPv4 Address:       $($adapter.IPv4Address.IPAddress)"

        $macInfo = Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq $adapter.InterfaceDescription }
        if ($macInfo) {
            $output += "MAC Address:        $($macInfo.MacAddress)"
            $output += "Status:             $($macInfo.Status)"
            $statusColor = if ($macInfo.Status -eq "Up") { "Green" } else { "Red" }
            Write-Item "Adapter:" $adapter.InterfaceAlias
            Write-Item "IPv4 Address:" $adapter.IPv4Address.IPAddress
            Write-Item "MAC Address:" $macInfo.MacAddress
            Write-Host ("{0,-22} {1}" -f "Status:", $macInfo.Status) -ForegroundColor $statusColor
        }
    }

    Write-Section "WINDOWS UPDATE SETTINGS"
    $output += "`n=== WINDOWS UPDATE SETTINGS ==="
    if ($isAdmin) {
        try {
            $wuau = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
            switch ($wuau.AUOptions) {
                1 { $status = "Never check for updates" }
                2 { $status = "Notify before downloading" }
                3 { $status = "Auto download and notify to install" }
                4 { $status = "Auto download and schedule the install" }
                Default { $status = "Unknown setting ($($wuau.AUOptions))" }
            }
            Write-Item "Automatic Updates:" $status
            $output += "Automatic Updates:  $status"
        } catch {
            Write-Host "Warning: Unable to access update settings." -ForegroundColor Red
            $output += "Warning: Unable to access update settings."
        }
    } else {
        Write-Host "Skipped: Requires admin privileges to check update settings." -ForegroundColor DarkYellow
        $output += "Skipped: Requires admin privileges to check update settings."
    }

    $export = Read-Host "`nWould you like to export this scan? (yes/no)"
    if ($export -match '^y') {
        Ensure-ExportFolder
        $fileBase = "system_scan"
        $filePath = Join-Path $exportFolder "$fileBase.txt"
        $output | Out-File $filePath
        Write-Host "Export saved to: $(Resolve-Path $filePath)" -ForegroundColor DarkCyan

        $logChoice = Read-Host "Would you like to create a log file? (yes/no)"
        if ($logChoice -match '^y') {
            $logPath = Join-Path $exportFolder "system_log.txt"
            "System scan completed on $(Get-Date)" | Out-File $logPath
            "Saved to: $filePath" | Out-File $logPath -Append
            Write-Host "Log created at: $(Resolve-Path $logPath)" -ForegroundColor DarkGreen
        }
    }
}

function Run-SBOMScan {
    Write-Section "INSTALLED SOFTWARE INVENTORY"

    $softwareList = @()
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        try {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher
            $softwareList += $items
        } catch {
            Write-Host "Warning: Failed to query $path" -ForegroundColor DarkYellow
        }
    }

    $keywords = @{
        Applications   = @("microsoft", "adobe", "oracle", "java", "zoom", "vlc", "chrome", "firefox")
        Drivers        = @("driver", "chipset", "firmware", "redistributable", "utility")
        Toolbars       = @("toolbar", "search", "ask", "bing", "yahoo", "extension")
        Security       = @("carbon black", "sentinelone", "defender", "mcafee", "sophos", "avast")
        RemoteAccess   = @("teamviewer", "anydesk", "vnc", "logmein", "radmin")
        Medical        = @("philips", "intellispace", "carestream", "medtronic", "ge healthcare")
    }
    $categories = @{ Applications=@(); Drivers=@(); Toolbars=@(); Security=@(); RemoteAccess=@(); Medical=@(); Unknown=@() }

    foreach ($item in $softwareList) {
        $name = $item.DisplayName.ToLower()
        $matched = $false
        foreach ($category in $keywords.Keys) {
            if ($keywords[$category] | Where-Object { $name -like "*$_*" }) {
                $categories[$category] += $item
                $matched = $true
                break
            }
        }
        if (-not $matched) { $categories["Unknown"] += $item }
    }

    foreach ($category in $categories.Keys) {
        if ($categories[$category].Count) {
            Write-CategoryHeader $category
            $categories[$category] | Sort-Object DisplayName | Format-Table -AutoSize
        }
    }

    $export = Read-Host "`nWould you like to export this SBOM? (yes/no)"
    if ($export -match '^y') {
        Ensure-ExportFolder
        $fileBase = "sbom_scan"
        $csv = Join-Path $exportFolder "$fileBase.csv"
        $json = Join-Path $exportFolder "$fileBase.json"
        $txt = Join-Path $exportFolder "$fileBase.txt"

        $softwareList | Export-Csv $csv -NoTypeInformation -Encoding UTF8
        $softwareList | ConvertTo-Json -Depth 3 | Out-File $json
        $softwareList | Format-Table -AutoSize | Out-File $txt

        Write-Host "CSV:  $(Resolve-Path $csv)" -ForegroundColor Blue
        Write-Host "JSON: $(Resolve-Path $json)" -ForegroundColor Green
        Write-Host "TXT:  $(Resolve-Path $txt)" -ForegroundColor White

        $logChoice = Read-Host "Would you like to create a log file? (yes/no)"
        if ($logChoice -match '^y') {
            $logPath = Join-Path $exportFolder "sbom_log.txt"
            "SBOM scan completed on $(Get-Date)" | Out-File $logPath
            "CSV:  $csv" | Out-File $logPath -Append
            "JSON: $json" | Out-File $logPath -Append
            "TXT:  $txt" | Out-File $logPath -Append
            Write-Host "Log created at: $(Resolve-Path $logPath)" -ForegroundColor DarkGreen
        }
    }
}

# --- Entry Point ---
Write-Host @"
System Scanning Toolkit
------------------------
This tool collects and displays key information about the current Windows device.

Features:
- Admin privilege detection
- System, OS, and Network inventory
- Software categorization
- Flexible export to CSV, JSON, and TXT
- Optional logging

All operations are local and read-only.
"@ -ForegroundColor Yellow

do {
    Show-Menu
    $choice = Read-Host "Enter choice (0, 1, or 2)"

    if ($choice -eq "0") {
        Write-Host "Exiting... Goodbye." -ForegroundColor Cyan
        break
    }

    Run-AdminCheck

    switch ($choice) {
        "1" { Run-SystemScan }
        "2" { Run-SBOMScan }
        default { Write-Host "Invalid selection. Please try again." -ForegroundColor DarkRed }
    }

    $again = Read-Host "`nWould you like to run another scan? (yes/no)"
    $repeat = $again -match '^y'

} while ($repeat)
