# kb hash checker

<#
.SYNOPSIS
    Verify file integrity by comparing a Microsoft-provided base64-encoded hash with the locally computed hash of a file.

.DESCRIPTION
    This script prompts the user to:
    - Choose a hashing algorithm (SHA1 or SHA256)
    - Enter a Microsoft base64-encoded hash
    - Select a file to hash
    It then decodes the Microsoft hash, converts it to hexadecimal, computes the local hash of the selected file using the chosen algorithm,
    compares the two, and outputs the results.

.NOTES
    Author: Katie Paz
    Created: 2025-05-29
#>

# kb-hash-manual.ps1

<#
.SYNOPSIS
    Verify local file integrity against a manually provided Microsoft base64-encoded hash.

.DESCRIPTION
    - Asks for algorithm and base64-encoded hash
    - Computes local file hash
    - Compares and optionally saves results
#>

function Decode-Base64ToHex($base64) {
    $bytes = [Convert]::FromBase64String($base64)
    return -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

function Get-HashAlgorithmObject {
    param([string]$algorithm)

    switch ($algorithm.ToLower()) {
        "sha1"   { return [System.Security.Cryptography.SHA1]::Create() }
        "sha256" { return [System.Security.Cryptography.SHA256]::Create() }
        default  {
            Write-Host "Unsupported algorithm: $algorithm" -ForegroundColor Red
            exit
        }
    }
}

function Prompt-FilePath {
    $mode = Read-Host "Do you have the full path to the file? (yes/no)"
    if ($mode -match '^(y|yes)$') {
        $raw = Read-Host "Enter full path to the file you'd like to hash"
        return $raw.Trim('"')  # Strip quotes
    }

    $searchHere = Read-Host "Is the file in the current directory? (yes/no)"
    if ($searchHere -match '^(y|yes)$') {
        $startDir = Get-Location
    } else {
        $downloadsCheck = Read-Host "Is the file in the Downloads directory? (yes/no)"
        if ($downloadsCheck -match '^(y|yes)$') {
            $startDir = Join-Path $HOME "Downloads"
        } else {
            $startDir = $HOME
            while ($true) {
                Write-Host "`nScanning: $startDir"
                $dirs = Get-ChildItem -Path $startDir -Directory | Select-Object -ExpandProperty Name
                if ($dirs.Count -eq 0) { break }

                Write-Host "`nSubdirectories:"
                $i = 1
                foreach ($d in $dirs) {
                    Write-Host "[$i] $d"
                    $i++
                }
                Write-Host "[0] Stay in current directory"
                Write-Host "[X] Other - Enter full path manually"

                $choice = Read-Host "Choose directory number or option"
                if ($choice -eq "0") { break }
                elseif ($choice -match '^\d+$' -and $choice -ge 1 -and $choice -le $dirs.Count) {
                    $startDir = Join-Path $startDir $dirs[$choice - 1]
                }
                elseif ($choice -match '^[xX]$') {
                    $manualPath = Read-Host "Enter full path to your desired directory"
                    $manualPath = $manualPath.Trim('"')
                    if (Test-Path $manualPath -PathType Container) {
                        $startDir = $manualPath
                        break
                    } else {
                        Write-Host "Invalid path entered. Try again." -ForegroundColor Red
                    }
                } else {
                    Write-Host "Invalid selection." -ForegroundColor Red
                }
            }
        }
    }

    $files = Get-ChildItem -Path $startDir -File | Select-Object -ExpandProperty Name
    if ($files.Count -eq 0) {
        Write-Host "No files found in selected directory." -ForegroundColor Red
        exit
    }

    $files | ForEach-Object -Begin { $i = 1 } -Process { Write-Host "[$i] $_"; $i++ }
    $choice = Read-Host "Choose file number"
    return Join-Path $startDir $files[$choice - 1]
}


# === Main ===
$kb = Read-Host "Enter KB number (for reference only)"
$algorithm = Read-Host "Enter hash algorithm (sha1 or sha256)"
$expectedBase64 = Read-Host "Enter Microsoft base64 hash"
$expectedHex = Decode-Base64ToHex $expectedBase64

$filePath = Prompt-FilePath
if (!(Test-Path $filePath)) {
    Write-Host "File not found: $filePath" -ForegroundColor Red
    exit
}

Write-Host "[*] Hashing local file..."
$hasher = Get-HashAlgorithmObject -algorithm $algorithm
$stream = [System.IO.File]::OpenRead($filePath)
$actualHash = $hasher.ComputeHash($stream)
$stream.Close()
$actualHex = -join ($actualHash | ForEach-Object { $_.ToString("x2") })

Write-Host "`nResults:"
Write-Host "Microsoft $algorithm hash: $expectedHex"
Write-Host "Local file $algorithm hash: $actualHex"

if ($expectedHex -ieq $actualHex) {
    Write-Host "`n[OK] Hash match confirmed." -ForegroundColor Green
    $match = "MATCH"
} else {
    Write-Host "`n[FAIL] Hash mismatch." -ForegroundColor Yellow
    $match = "MISMATCH"
}

$save = Read-Host "`nWould you like to save results to a .txt file? (yes/no)"
if ($save -match '^(y|yes)$') {
    $outPath = "KB$kb-hashcheck.txt"
    Set-Content -Path $outPath -Value @(
        "KB: $kb",
        "Algorithm: $algorithm",
        "Expected Hash: $expectedHex",
        "Computed Hash: $actualHex",
        "Match Result: $match",
        "Local File: $filePath"
    )
    Write-Host "Saved results to $outPath"
}

Write-Host "`nDone. Press any key to exit..."
[void][System.Console]::ReadKey($true)
