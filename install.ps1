<#
.SYNOPSIS
    Installs AGYX for the current user into %LOCALAPPDATA%\Programs\agyx
    and adds it to the User PATH via the Windows Registry (HKCU\Environment).

.DESCRIPTION
    - Requires no administrator privileges.
    - Idempotent: safe to run multiple times.
    - Preserves existing PATH entries and preserves REG_EXPAND_SZ value type.
    - Does NOT use setx (avoids 1024-character truncation).
    - Broadcasts environment change to all top-level windows.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "Installing AGYX..." -ForegroundColor Cyan

# 1. Determine install directory
$installDir = Join-Path $env:LOCALAPPDATA "Programs\agyx"
$targetExe = Join-Path $installDir "agyx.exe"

# 2. Locate or build binary
$repoRoot = $PSScriptRoot
$releaseExe = Join-Path $repoRoot "target\release\agyx.exe"

if (-not (Test-Path $releaseExe)) {
    Write-Host "Building release binary with cargo..." -ForegroundColor Yellow
    Push-Location $repoRoot
    try {
        & cargo build --release --bin agyx
        if ($LASTEXITCODE -ne 0) {
            throw "Cargo build failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $releaseExe)) {
    throw "Could not find binary at $releaseExe"
}

# 3. Create install directory and copy binary
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

Copy-Item -Path $releaseExe -Destination $targetExe -Force
Write-Host "Copied binary to: $targetExe" -ForegroundColor Green

# 4. Modify User PATH via Registry (HKCU\Environment) preserving REG_EXPAND_SZ
$regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $true)
if ($null -eq $regKey) {
    throw "Could not open HKCU\Environment registry key."
}

try {
    $currentPathRaw = $regKey.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $valKind = $regKey.GetValueKind("Path")

    # Ensure valid string
    if ($null -eq $currentPathRaw) {
        $currentPathRaw = ""
    }

    # Split into clean elements
    $pathParts = $currentPathRaw -split ';' | Where-Object { $_.Trim().Length -gt 0 }

    # Check if already in PATH (case-insensitive normalization)
    $alreadyPresent = $false
    foreach ($part in $pathParts) {
        if ($part.Trim().TrimEnd('\') -ieq $installDir.Trim().TrimEnd('\')) {
            $alreadyPresent = $true
            break
        }
    }

    if ($alreadyPresent) {
        Write-Host "PATH check: $installDir is already in User PATH." -ForegroundColor Green
    } else {
        # Append install directory
        $newPath = if ($currentPathRaw.Trim().Length -gt 0) {
            "$currentPathRaw;$installDir"
        } else {
            $installDir
        }

        # Preserve REG_EXPAND_SZ (or REG_SZ)
        $regKey.SetValue("Path", $newPath, $valKind)
        Write-Host "Added $installDir to User PATH in HKCU\Environment (preserved $valKind)." -ForegroundColor Green

        # Update current process PATH
        $env:PATH = "$env:PATH;$installDir"

        # 5. Broadcast WM_SETTINGCHANGE
        Write-Host "Broadcasting environment change..." -ForegroundColor Gray
        try {
            Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
                [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
                public static extern System.IntPtr SendMessageTimeout(
                    System.IntPtr hWnd,
                    uint Msg,
                    System.UIntPtr wParam,
                    string lParam,
                    uint fuFlags,
                    uint uTimeout,
                    out System.UIntPtr lpdwResult
                );
"@ -ErrorAction SilentlyContinue
            $HWND_BROADCAST = [System.IntPtr]0xffff
            $WM_SETTINGCHANGE = 0x001a
            $result = [System.UIntPtr]::Zero
            [Win32.NativeMethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [System.UIntPtr]::Zero, "Environment", 2, 5000, [ref]$result) | Out-Null
        } catch {
            # Ignore broadcast errors if native call is unavailable
        }
    }
} finally {
    $regKey.Close()
}

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Green
Write-Host " AGYX installed successfully!" -ForegroundColor Green
Write-Host " Binary: $targetExe" -ForegroundColor White
Write-Host "===========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Please open a NEW terminal window to use 'agyx' from anywhere." -ForegroundColor Yellow
Write-Host "You can test with: agyx --version" -ForegroundColor Cyan
