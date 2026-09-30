<#
.SYNOPSIS
    Uninstalls AGYX: removes the binary and the exact User PATH registry entry.

.DESCRIPTION
    - Preserves all vault profiles, encryption keys, and configuration by default.
    - Leaves your live AGY credential untouched.
    - If -PurgeData is passed, prompts for confirmation before deleting vault and settings.
#>

[CmdletBinding()]
param(
    [switch]$PurgeData
)

$ErrorActionPreference = "Stop"

Write-Host "Uninstalling AGYX..." -ForegroundColor Cyan

# 1. Target directory
$installDir = Join-Path $env:LOCALAPPDATA "Programs\agyx"
$targetExe = Join-Path $installDir "agyx.exe"

# 2. Remove binary
if (Test-Path $targetExe) {
    Remove-Item -Path $targetExe -Force
    Write-Host "Removed binary: $targetExe" -ForegroundColor Green
}

# Remove directory if empty
if (Test-Path $installDir) {
    $items = Get-ChildItem -Path $installDir -Force
    if ($items.Count -eq 0) {
        Remove-Item -Path $installDir -Force -Recurse
        Write-Host "Removed empty directory: $installDir" -ForegroundColor Green
    }
}

# 3. Remove from User PATH in Registry (HKCU\Environment)
$regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $true)
if ($null -ne $regKey) {
    try {
        $currentPathRaw = $regKey.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $valKind = $regKey.GetValueKind("Path")

        if ($currentPathRaw) {
            $pathParts = $currentPathRaw -split ';' | Where-Object {
                $_.Trim().Length -gt 0 -and
                $_.Trim().TrimEnd('\') -ine $installDir.Trim().TrimEnd('\')
            }
            $newPath = $pathParts -join ';'

            $regKey.SetValue("Path", $newPath, $valKind)
            Write-Host "Removed AGYX from User PATH in HKCU\Environment." -ForegroundColor Green

            # Broadcast change
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
                # Ignore
            }
        }
    } finally {
        $regKey.Close()
    }
}

# 4. Handle vault / data directory
$dataDir = Join-Path $env:APPDATA "agyx"

if ($PurgeData) {
    Write-Host ""
    Write-Host "WARNING: -PurgeData was requested." -ForegroundColor Red
    Write-Host "This will permanently remove your stored AGYX profiles at: $dataDir" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'yes' to permanently erase all AGYX profiles and settings"
    if ($confirm -eq "yes") {
        if (Test-Path $dataDir) {
            Remove-Item -Path $dataDir -Force -Recurse
            Write-Host "Erased AGYX data directory: $dataDir" -ForegroundColor Green
        }
    } else {
        Write-Host "Data purge cancelled. Preserved vault and configuration." -ForegroundColor Cyan
    }
} else {
    Write-Host ""
    Write-Host "Note: Your saved profiles and vault in '$dataDir' were left untouched." -ForegroundColor Cyan
    Write-Host "To remove them, delete '$dataDir' manually or run with -PurgeData." -ForegroundColor Gray
}

Write-Host ""
Write-Host "AGYX uninstallation complete." -ForegroundColor Green
