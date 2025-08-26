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
$deviceInfo = @{}
Write-Host "`n"
Write-Host "                    SYSTEM SCANNING TOOLKIT                    " -ForegroundColor DarkYellow -BackGroundColor Magenta
Write-Host "---------------------------------------------------------------`n" -ForegroundColor DarkMagenta
Write-Host "This tool collects and displays the following information for the current Windows device." -ForegroundColor White -BackgroundColor Black
Write-Host "     * System, OS, and Network inventory" -ForegroundColor Cyan -BackgroundColor Black
Write-Host "     * Hotfixes (NOTE: must be run as Administrator for hotfix info)" -ForegroundColor Yellow -BackgroundColor Black
Write-Host "     * Installed 32-bit and 64-bit programs (DisplayName, DisplayVersion, Publisher)" -ForegroundColor Green -BackgroundColor Black
Write-Host "`nNOTE: Software inventory is NOT displayed on screen. It is ONLY included in exports." -ForegroundColor Blue -BackgroundColor Black
Write-Host "Option to Export to: TXT, CSV, and/or JSON`n" -ForegroundColor Blue -BackgroundColor Black
Write-Host "             All operations are LOCAL and READ-ONLY             " -ForegroundColor Yellow -BackGroundColor DarkRed
Write-Host "---> This tool will NOT make any changes to the configuration of the device <---`n" -ForegroundColor DarkYellow -BackgroundColor Black
Write-Host "-------------     FILE EXPORT NAME     -------------" -ForegroundColor DarkMagenta -BackGroundColor Green
Write-Host "What would you like to name your result file(s)?`n" -ForegroundColor White -BackGroundColor Black
Write-Host "Option 1: MAC Address naming" -ForegroundColor Cyan -BackgroundColor Black
Write-Host "Option 2: Custom filename`n" -ForegroundColor Yellow -BackgroundColor Black
do {
    $fileNameChoice = Read-Host "Enter Option 1 or 2"
    $fileNameChoice = $fileNameChoice.Trim().ToLower()
    if ($fileNameChoice -ne "1" -and $fileNameChoice -ne "2") {
        Write-Host "Invalid input. Please enter 1 or 2." -ForegroundColor DarkYellow -BackGroundColor DarkRed
    }
} while ($fileNameChoice -ne "1" -and $fileNameChoice -ne "2")
if ($fileNameChoice -eq "1") {
    Write-Host "`nMAC-based naming selected. The script will generate the result file name automatically." -ForegroundColor Cyan -BackgroundColor Black
    $baseFileName = "auto_mac"
} else {
    $baseFileName = Read-Host "Enter your custom name for the results file (no extension)"
    $baseFileName = $baseFileName.Trim().ToLower()
    Write-Host "Custom file base name set to: $baseFileName" -ForegroundColor Yellow -BackgroundColor Black
}
Write-Host "`n-------------      FILE EXPORT TYPE      -------------" -ForegroundColor DarkMagenta -BackGroundColor Green 
Write-Host "Which format would you like to export the results to?`n" -ForegroundColor White -BackGroundColor Black
Write-Host "Option 1: TXT (.txt)" -ForegroundColor Cyan -BackgroundColor Black
Write-Host "Option 2: CSV (.csv)" -ForegroundColor Green -BackgroundColor Black
Write-Host "Option 3: JSON (.json)`n" -ForegroundColor Yellow -BackgroundColor Black
$validFormats = @("1", "2", "3", "txt", "csv", "json")
$exportChoices = @()
do {
    Write-Host "NOTE: You can choose multiple (e.g. 1,2,3 or txt,csv,json)`n"
    $rawInput = Read-Host "Enter your choices (leave blank for all 3)"
    $normalized = $rawInput.ToLower().Trim() -replace '\s+', ''
    if ($normalized -eq "") {
        $exportChoices = @("txt", "csv", "json")
        break
    }
    $parts = $normalized -split '[,;]'
    $invalid = $parts | Where-Object { $_ -notin $validFormats }
    if ($invalid.Count -gt 0) {
        Write-Host "`nInvalid option(s): $($invalid -join ', '). Please try again." -ForegroundColor DarkYellow -BackGroundColor DarkRed
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
Write-Host "Export formats selected:`n $($exportChoices -join ', ')" -ForegroundColor Red -BackgroundColor Black
Write-Host "`n--------    HELPFUL DEVICE DETAILS    -------- " -ForegroundColor DarkMagenta -BackGroundColor Green
Write-Host "              OPTIONAL fields          `n" -ForegroundColor Blue -BackgroundColor Black
$deviceInfo["Make"] = (Read-Host -Prompt "Enter Make (e.g., GE)").Trim().ToLower()
$deviceInfo["Model"] = (Read-Host -Prompt "Enter Model (e.g., LOGIQ E10)").Trim().ToLower()
$deviceInfo["Type"] = (Read-Host -Prompt "Enter Type (e.g., Ultrasound)").Trim().ToLower()
$deviceInfo["Hospital"] = (Read-Host -Prompt "Enter Hospital (e.g., Cleveland)").Trim().ToLower()
$deviceInfo["Department"] = (Read-Host -Prompt "Enter Department (e.g., emergency)").Trim().ToLower()
$deviceInfo["DispatchPerson"] = (Read-Host -Prompt "Enter Dispatch Person (e.g., John Smith)").Trim().ToLower()
$deviceInfo["DT"] = (Read-Host -Prompt "Enter Associated DT (e.g., DT-123456)").Trim().ToLower()
$deviceInfo["CIM"] = (Read-Host -Prompt "Enter Associated CIM (e.g., CIM-123456)").Trim().ToLower()
Write-Host "`nThank you. The scan will now begin and results will be saved as: $baseFileName .txt / .csv / .json" -ForegroundColor Blue -BackgroundColor Black
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
        Write-Host "Skipped: Requires admin privileges to retrieve hotfixes." -ForegroundColor DarkYellow -BackGroundColor DarkRed
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
$output = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss" # Add timestamp and device info
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
$output += "`n=== START SCAN RESULTS ==="
$output += Run-SystemScan
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
    $baseFileName = ($plainMacs -join "_and_")
    Write-Host "`nMAC-based filename generated: $baseFileName" -ForegroundColor Cyan
}
$baseDir = Join-Path -Path $PSScriptRoot -ChildPath $baseFileName # Create output directory
if (-not (Test-Path $baseDir)) {
    New-Item -ItemType Directory -Path $baseDir | Out-Null
}
Write-Host "`nAll files saved to:`n" -ForegroundColor Blue
Write-Host "---------->   $baseDir   <---------" -ForegroundColor DarkBlue -BackGroundColor Green
if ($exportChoices -contains "txt") {
    $txtPath = Join-Path -Path $baseDir -ChildPath "$baseFileName.txt"
    $output | Out-File -FilePath $txtPath -Encoding UTF8
    Write-Host "`nSaved TXT" -ForegroundColor Cyan
}
if ($exportChoices -contains "csv") {
    $csvPath = Join-Path -Path $baseDir -ChildPath "$baseFileName.csv"
    $output | ForEach-Object { [PSCustomObject]@{ Result = $_ } } |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Saved CSV" -ForegroundColor Green
}
if ($exportChoices -contains "json") {
    $jsonPath = Join-Path -Path $baseDir -ChildPath "$baseFileName.json"
    $output | ConvertTo-Json -Depth 2 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "Saved JSON`n" -ForegroundColor Yellow
}
