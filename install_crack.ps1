<#
    Fences 6 (6.5.2.7) licence bypass - installer  (SHIM method)
    =====================================================================
    Principle: Fences.exe itself is left untouched, because the app verifies
    its own Authenticode signature (WinTrust) and shows a "your installation
    integrity is compromised" dialog if the binary was modified.

    Instead the licence glue assembly is replaced:
        Stardock.ApplicationServices.dll
    Fences consumes only four public types from it
        (LicenseState / LicenseInformation / Result / Sas),
    and the shim keeps the assembly version Fences references (1.10.4.128),
    so the loader binds to it with no binding redirect.

    The shim reports a permanent licence, therefore:
        - no Stardock-RSA-signed License.sig is required
        - the native SAS engine (SdAppServices*.dll) is never invoked
        - the activation / trial UI never appears

    Usage (ELEVATED PowerShell):
        powershell -NoProfile -ExecutionPolicy Bypass -File .\install_crack.ps1
    Roll back (needs the pristine glue assembly in .\original\):
        powershell -NoProfile -ExecutionPolicy Bypass -File .\install_crack.ps1 -Restore
#>
[CmdletBinding()]
param(
    [string]$ShimSource    = (Join-Path $PSScriptRoot 'shim\Stardock.ApplicationServices.dll'),
    # pristine copy of Stardock's original glue assembly, used by -Restore
    [string]$OriginalSource = (Join-Path $PSScriptRoot 'original\Stardock.ApplicationServices.dll'),
    [string]$InstallDir    = 'C:\Program Files (x86)\Stardock\Fences',
    [string]$ExpectShimHash = 'FAD78437C0E34D2A77509B06395F4CB65C9F38AB2999CD2BF0E7603AD702EA81',
    [string]$OrigExeHash    = '748760CFAB6C314560CA54D938D3E5BE6F69AD078E8356A4FA857DCFDE4A14E7',
    [string]$PatchedExeHash = 'A5BAE89E3B4A10C09C1C5A6EC86F4911A91E35BB49CA34B7EC5E1AB1AE4CE9A7',
    [switch]$Restore
)

$ErrorActionPreference = 'Stop'

$exe = Join-Path $InstallDir 'Fences.exe'
$dll = Join-Path $InstallDir 'Stardock.ApplicationServices.dll'
$cfg = Join-Path $InstallDir 'Fences.exe.config'

$cfgOriginal = @'
<?xml version="1.0"?>
<configuration>
  <configSections>
  </configSections>
  <startup  useLegacyV2RuntimeActivationPolicy="true">
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.0,Profile=Client" />
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.0"/>
    <supportedRuntime version="v2.0.50727"/>
  </startup>
</configuration>
'@

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host '[X] Administrator rights required. Right-click PowerShell -> Run as administrator.' -ForegroundColor Red
        exit 1
    }
}

function Get-Sha256([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }

function Initialize-RestartManager {
    if ($script:rmReady) { return }
    $sig = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class FxRM2 {
    [StructLayout(LayoutKind.Sequential)] public struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=64)] public string strServiceShortName;
        public int ApplicationType; public uint AppStatus; public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }
    [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] public static extern int RmStartSession(out uint h, int f, string k);
    [DllImport("rstrtmgr.dll")] public static extern int RmEndSession(uint h);
    [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] public static extern int RmRegisterResources(uint h, uint nf, string[] f, uint na, RM_UNIQUE_PROCESS[] a, uint ns, string[] s);
    [DllImport("rstrtmgr.dll")] public static extern int RmGetList(uint h, out uint need, ref uint cnt, [In,Out] RM_PROCESS_INFO[] arr, ref uint reasons);
    public static int[] Who(string path) {
        var pids = new List<int>();
        uint session; if (RmStartSession(out session, 0, Guid.NewGuid().ToString()) != 0) return pids.ToArray();
        try {
            if (RmRegisterResources(session, 1, new string[] { path }, 0, null, 0, null) != 0) return pids.ToArray();
            uint need = 0, cnt = 0, rs = 0;
            if (RmGetList(session, out need, ref cnt, null, ref rs) != 234) return pids.ToArray();
            var arr = new RM_PROCESS_INFO[need]; cnt = need;
            if (RmGetList(session, out need, ref cnt, arr, ref rs) != 0) return pids.ToArray();
            for (int i = 0; i < cnt; i++) pids.Add(arr[i].Process.dwProcessId);
        } finally { RmEndSession(session); }
        return pids.ToArray();
    }
}
"@
    Add-Type -TypeDefinition $sig -ErrorAction Stop
    $script:rmReady = $true
}

function Stop-Fences {
    foreach ($n in 'Fences', 'FencesCLI', 'SdDisplay', 'FencesTaskbarItem') {
        foreach ($p in (Get-Process -Name $n -ErrorAction SilentlyContinue)) {
            try { Write-Host ("[*] stopping {0} (PID {1})" -f $p.ProcessName, $p.Id); Stop-Process -Id $p.Id -Force } catch {}
        }
    }
    Start-Sleep -Milliseconds 800
    try {
        Initialize-RestartManager
        foreach ($target in @($exe, $dll)) {
            foreach ($lpid in @([FxRM2]::Who($target))) {
                $p = Get-Process -Id $lpid -ErrorAction SilentlyContinue
                if ($p) { Write-Host ("[*] stopping file holder {0} (PID {1})" -f $p.ProcessName, $p.Id); Stop-Process -Id $p.Id -Force }
            }
        }
    } catch {}
    Start-Sleep -Milliseconds 1000
}

function Install-Crack {
    if (-not (Test-Path -LiteralPath $ShimSource)) { throw "shim not found: $ShimSource" }
    if (-not (Test-Path -LiteralPath $exe)) { throw "Fences.exe not found: $exe (is Fences 6 installed?)" }

    $srcHash = Get-Sha256 $ShimSource
    Write-Host ("[*] shim DLL : {0}" -f $ShimSource)
    Write-Host ("    SHA256   : {0}" -f $srcHash)
    if ($ExpectShimHash -and $srcHash -ne $ExpectShimHash) { throw "shim SHA256 mismatch (expected $ExpectShimHash)" }

    # main binary must be the pristine signed build
    $exeHash = Get-Sha256 $exe
    Write-Host ("[*] Fences.exe: {0}" -f $exeHash)
    if ($exeHash -eq $PatchedExeHash) {
        $bak = @(Get-ChildItem -LiteralPath $InstallDir -Filter 'Fences.exe.bak_*' | Sort-Object Name | Select-Object -First 1)
        if ($bak.Count -eq 0) { throw 'Fences.exe is the patched build but no Fences.exe.bak_* backup exists' }
        Stop-Fences
        [System.IO.File]::Copy($bak[0].FullName, $exe, $true)
        Write-Host ("[+] restored pristine signed Fences.exe (from {0})" -f $bak[0].Name) -ForegroundColor Green
        $exeHash = Get-Sha256 $exe
    }
    if ($OrigExeHash -and $exeHash -ne $OrigExeHash) {
        Write-Host '[!] Fences.exe is not the known 6.5.2.7 build (different version or modified by something else).' -ForegroundColor Yellow
        if ((Read-Host '    Continue anyway? [y/N]') -notmatch '^(y|Y)') { Write-Host '[x] cancelled'; return }
    }

    if ((Get-Sha256 $dll) -eq $srcHash) {
        Write-Host '[=] shim already installed' -ForegroundColor Green
    } else {
        Stop-Fences
        $dllBak = "$dll.bak"
        if (-not (Test-Path -LiteralPath $dllBak)) {
            Copy-Item -LiteralPath $dll -Destination $dllBak -Force
            Write-Host ("[+] backed up original glue assembly -> {0}" -f $dllBak) -ForegroundColor Green
        }
        [System.IO.File]::Copy($ShimSource, $dll, $true)
        if ((Get-Sha256 $dll) -ne $srcHash) { throw 'post-write verification failed' }
        Write-Host '[+] shim installed' -ForegroundColor Green
    }

    # pristine app config: the shim carries version 1.10.4.128, so no redirect is needed
    [System.IO.File]::WriteAllText($cfg, $cfgOriginal)
    Write-Host '[+] Fences.exe.config restored to the shipped content' -ForegroundColor Green

    try {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Stardock\Fences' -Name 'IsRegistered' -Value 1 -Type DWord -ErrorAction Stop
        Write-Host '[+] HKLM\SOFTWARE\Stardock\Fences\IsRegistered = 1' -ForegroundColor Green
    } catch {}

    Write-Host ''
    Write-Host 'Done. Start Fences 6 - all Pro features unlocked, no activation prompt,' -ForegroundColor Cyan
    Write-Host 'and no "integrity compromised" warning (the main binary is untouched).' -ForegroundColor Cyan
}

function Restore-Original {
    $dllBak = "$dll.bak"
    $src = $null
    if (Test-Path -LiteralPath $dllBak)                               { $src = $dllBak }
    elseif (Test-Path -LiteralPath $OriginalSource)                   { $src = $OriginalSource }
    if (-not $src) {
        throw "no original glue assembly found. Looked for:`n  $dllBak`n  $OriginalSource`nCopy the pristine Stardock.ApplicationServices.dll next to this script (original\Stardock.ApplicationServices.dll)."
    }
    Stop-Fences
    [System.IO.File]::Copy($src, $dll, $true)
    [System.IO.File]::WriteAllText($cfg, $cfgOriginal)
    Write-Host ("[+] restored original glue assembly from {0}" -f $src) -ForegroundColor Green
    Write-Host ("    SHA256 = {0}" -f (Get-Sha256 $dll)) -ForegroundColor Green
}

Assert-Admin
if ($Restore) { Restore-Original } else { Install-Crack }
