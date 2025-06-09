# ------------------[ Helper Functions ]------------------

function Write-Section {
    param (
        [string]$Title,
        [string]$Color = "Cyan"
    )
    Write-Host "`n=== $Title ===" -ForegroundColor $Color
}

function Write-Item {
    param (
        [string]$Label,
        [string]$Value,
        [string]$Color = "Gray",
        [int]$Width = 22
    )
    Write-Host ("{0,-$Width} {1}" -f $Label, $Value) -ForegroundColor $Color
}

# ------------------[ Initialization ]------------------

$deviceInfo = @{}

Write-Host "`nSystem Scanning Toolkit" -ForegroundColor Magenta
Write-Host "------------------------`n" -ForegroundColor Magenta

Write-Host "This tool collects and displays key information about the current Windows device.`n" -ForegroundColor Yellow

Write-Host "Features:" -ForegroundColor White
Write-Host "- System, OS, and Network inventory" -ForegroundColor Cyan
Write-Host "- Admin privilege detection" -ForegroundColor DarkYellow
Write-Host "- Recently installed hotfixes (if run as Administrator)" -ForegroundColor DarkYellow
Write-Host "- Installed 32-bit and 64-bit programs (DisplayName, DisplayVersion, Publisher)" -ForegroundColor Green
Write-Host "- Flexible export to TXT, CSV, and/or JSON`n" -ForegroundColor Blue

Write-Host "ALL OPERATIONS ARE LOCAL AND READ-ONLY. It will NOT make any changes to the configuration of the device.`n" -ForegroundColor White

Write-Host "RESULT FILES NAME: What would you like to name your results files?" -ForegroundColor Red
Write-Host "1 Let the script name your files with the MAC addresses of up to two active (Up) network adapters." -ForegroundColor Yellow
Write-Host "2 Enter your own custom base name for the results files (extensions will be added automatically).`n" -ForegroundColor Cyan

# File naming method selection
do {
    $fileNameChoice = Read-Host "Enter option 1 or 2"
    $fileNameChoice = $fileNameChoice.Trim().ToLower()
    if ($fileNameChoice -ne "1" -and $fileNameChoice -ne "2") {
        Write-Host "Invalid input. Please enter 1 or 2." -ForegroundColor DarkRed
    }
} while ($fileNameChoice -ne "1" -and $fileNameChoice -ne "2")

# Handle file naming logic
if ($fileNameChoice -eq "1") {
    Write-Host "MAC-based naming selected. The script will generate the result file name automatically." -ForegroundColor Green
    $baseFileName = "auto_mac"
} else {
    $baseFileName = Read-Host "Enter your custom base name for the results files (no extension)"
    $baseFileName = $baseFileName.Trim().ToLower()
    Write-Host "Custom file base name set to: $baseFileName" -ForegroundColor Green
}

Write-Host "`nWhich formats would you like to export the results to?" -ForegroundColor Red
Write-Host "1 TXT (.txt)" -ForegroundColor White
Write-Host "2 CSV (.csv)" -ForegroundColor White
Write-Host "3 JSON (.json)`n" -ForegroundColor White
Write-Host "You can choose multiple (e.g., 1,2,3 or csv,json,txt)." -ForegroundColor Yellow

$validFormats = @("1", "2", "3", "txt", "csv", "json")
$exportChoices = @()

do {
    $rawInput = Read-Host "Enter your choices (leave blank for all)"
    $normalized = $rawInput.ToLower().Trim() -replace '\s+', ''
    if ($normalized -eq "") {
        $exportChoices = @("txt", "csv", "json")
        break
    }
    $parts = $normalized -split '[,;]'
    $invalid = $parts | Where-Object { $_ -notin $validFormats }
    if ($invalid.Count -gt 0) {
        Write-Host "Invalid option(s): $($invalid -join ', '). Please try again." -ForegroundColor DarkRed
    } else {
        foreach ($choice in $parts) {
            switch ($choice) {
                "1" { $exportChoices += "txt" }
                "2" { $exportChoices += "csv" }
                "3" { $exportChoices += "json" }
                "txt" { $exportChoices += "txt" }
                "csv" { $exportChoices += "csv" }
                "json" { $exportChoices += "json" }
            }
        }
        $exportChoices = $exportChoices | Select-Object -Unique
    }
} while ($invalid.Count -gt 0 -or $exportChoices.Count -eq 0)

Write-Host "`nExport formats selected: $($exportChoices -join ', ')" -ForegroundColor Green

Write-Host "`nDEVICE DETAILS (not available through scans): Input fields below are OPTIONAL, but recommended for SOC and On-Site Personnel reference.`n" -ForegroundColor Red

$deviceInfo["Make"] = (Read-Host -Prompt "Enter Make (e.g., GE)").Trim().ToLower()
$deviceInfo["Model"] = (Read-Host -Prompt "Enter Model (e.g., LOGIQ E10)").Trim().ToLower()
$deviceInfo["Type"] = (Read-Host -Prompt "Enter Type (e.g., ultrasound)").Trim().ToLower()
$deviceInfo["Hospital"] = (Read-Host -Prompt "Enter Hospital (e.g., Cleveland)").Trim().ToLower()
$deviceInfo["Department"] = (Read-Host -Prompt "Enter Department (e.g., Emergency)").Trim().ToLower()
$deviceInfo["DispatchPerson"] = (Read-Host -Prompt "Enter Dispatch Person (e.g., John Smith)").Trim().ToLower()
$deviceInfo["DT"] = (Read-Host -Prompt "Enter Associated DT (e.g., DT-123456)").Trim().ToLower()
$deviceInfo["CIM"] = (Read-Host -Prompt "Enter Associated CIM (e.g., CIM-123456)").Trim().ToLower()

Write-Host "`nThank you. The scan will now begin and results will be saved as: $baseFileName.txt / .csv / .json" -ForegroundColor Blue

# ------------------[ System Scan Function ]------------------

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
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

    return $output
}

# ------------------[ Run Scan and Export Results ]------------------

$output = @()

# Add timestamp and device info
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$output += "`n=== SCAN TIMESTAMP ==="
$output += "$timestamp"
$output += ""
$output += "`n=== BEGIN DEVICE INFORMATION (user input) ==="
$orderedKeys = @("Make", "Model", "Type", "Hospital", "Department", "DispatchPerson", "DT", "CIM")
foreach ($key in $orderedKeys) {
    $output += ("{0,-18} {1}" -f "${key}:", $deviceInfo[$key])
}
$output += "=== END DEVICE INFORMATION ===`n"
$output += ""

# Run scan and append results
$output += "`n=== START SCAN RESULTS ==="
$output += Run-SystemScan

Write-Section "`nINSTALLED SOFTWARE INVENTORY"
$output += "`n=== INSTALLED SOFTWARE INVENTORY ==="

$softwareList = @()
$paths = @(
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
    "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
)

foreach ($path in $paths) {
    try {
        $items = @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" } |
            Select-Object DisplayName, DisplayVersion, Publisher)
        $softwareList += $items
    } catch {
        $output += "Error reading registry path: $path"
    }
}

# ✅ This was missing:
$total = $softwareList.Count
$output += "`nTotal collected software entries: $total"

if ($total -eq 0) {
    $output += "`nNo installed software found.`n"
} else {
    $softwareList = $softwareList | Sort-Object DisplayName
    foreach ($app in $softwareList) {
        $name = $app.DisplayName
        $version = if ($app.DisplayVersion) { $app.DisplayVersion } else { "N/A" }
        $publisher = if ($app.Publisher) { $app.Publisher } else { "N/A" }

        $line = "$name | Version: $version | Publisher: $publisher"
        $output += $line
    }
}

# Format MAC-based name if chosen
if ($fileNameChoice -eq "1") {
    $macAdapters = Get-NetAdapter |
        Where-Object { $_.Status -eq "Up" -and $_.MacAddress -ne $null } |
        Select-Object -First 2

    $colonMacs = @()
    $plainMacs = @()
    $nicNames = @()

    foreach ($adapter in $macAdapters) {
        $nicNames += $adapter.Name
        $colonMac = ($adapter.MacAddress -replace '-', ':').ToUpper()
        $plainMac = ($adapter.MacAddress -replace '-', '').ToUpper()
        $colonMacs += $colonMac
        $plainMacs += $plainMac
    }

    $nicSummary = if ($nicNames.Count -eq 1) {
        "`nUsing NIC Adapter '$($nicNames[0])' for file name. `nMAC Address: $($colonMacs[0])"
    } else {
        "`nUsing NIC Adapters '$($nicNames[0])' and '$($nicNames[1])' for file name.`n" +
        "$($nicNames[0]) MAC Address: $($colonMacs[0])`n$($nicNames[1]) MAC Address: $($colonMacs[1])"
    }

    Write-Host "`n$nicSummary" -ForegroundColor Yellow

    $baseFileName = ($plainMacs -join "_&_")
    Write-Host "`nMAC-based filename generated: $baseFileName" -ForegroundColor Cyan
}

# Create output directory
$baseDir = Join-Path -Path $PSScriptRoot -ChildPath $baseFileName
if (-not (Test-Path $baseDir)) {
    New-Item -ItemType Directory -Path $baseDir | Out-Null
}

# Save TXT
if ($exportChoices -contains "txt") {
    $txtPath = Join-Path -Path $baseDir -ChildPath "$baseFileName.txt"
    $output | Out-File -FilePath $txtPath -Encoding UTF8
    Write-Host "`nSaved TXT to: $txtPath" -ForegroundColor Green
}

# Save CSV (line-per-entry, under column "Result")
if ($exportChoices -contains "csv") {
    $csvPath = Join-Path -Path $baseDir -ChildPath "$baseFileName.csv"
    $output | ForEach-Object { [PSCustomObject]@{ Result = $_ } } |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nSaved CSV to: $csvPath" -ForegroundColor Green
}

# Save JSON (array of lines)
if ($exportChoices -contains "json") {
    $jsonPath = Join-Path -Path $baseDir -ChildPath "$baseFileName.json"
    $output | ConvertTo-Json -Depth 2 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "`nSaved JSON to: $jsonPath" -ForegroundColor Green
}

