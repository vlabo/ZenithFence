#requires -Version 5.1
<#
.SYNOPSIS
    Produce a product-named driver (e.g. nexufend-agent.sys) from the generically
    linked driver.sys / driver.lib, so the public repo never references the
    product name.

.DESCRIPTION
    The linked driver.sys carries NO internal reference to its own output file
    name (no module name, no export-table name). The only name-bearing field in
    the PE is the CodeView debug record's PDB path. So "rebrand" means: name the
    files, fix that PDB pointer, and (because kernel images are checksum-checked
    at load) recompute the PE checksum.

    Two modes:

      Re-link (default) -- link.exe is run again from the committed driver.lib
        with the product OUT/PDB names. Produces a byte-correct image: correct
        checksum, /INTEGRITYCHECK hash, and PDB pointer, with zero patching.
        Requires the MSVC toolchain (link.exe on PATH) and the libs in the repo.

      -PatchOnly -- takes an already-linked driver.sys/.pdb, renames them, patches
        the embedded PDB path in place, and recomputes the checksum. Use when you
        only have the linked artifact and no toolchain. The new PDB file name must
        fit the byte slot the linker reserved for the original, so link the source
        binary with a /PDBALTPATH at least as long as "<Name>.pdb".

    Signing is never done here by default: it needs the DriverCertificate private
    key. Pass -Sign to sign after rebranding (order matters: patch -> checksum ->
    sign, so the Authenticode hash covers the final bytes).

.EXAMPLE
    pwsh ./scripts/rebrand-driver.ps1 -Name nexufend-agent
    Re-link driver.lib into nexufend-agent.sys (+ .pdb).

.EXAMPLE
    pwsh ./scripts/rebrand-driver.ps1 -Name nexufend-agent -PatchOnly -Sign
    Rebrand the existing driver.sys artifact and sign it.
#>
[CmdletBinding()]
param(
    # Product name (no extension). Kept out of committed files -- pass it in.
    [Parameter(Mandatory)] [string] $Name,

    # Inputs produced by the generic link step.
    [string] $Lib = "driver.lib",
    [string] $Sys = "driver.sys",
    [string] $Pdb = "driver.pdb",

    # Rebrand the linked artifact in place instead of re-linking from the .lib.
    [switch] $PatchOnly,

    # Sign the result (needs the DriverCertificate private key in PrivateCertStore).
    [switch] $Sign
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    $outSys = "$Name.sys"
    $outPdb = "$Name.pdb"

    if (-not $PatchOnly) {
        # ---- Re-link mode -------------------------------------------------------
        if (-not (Test-Path $Lib)) { throw "Missing $Lib (run the build/link step first)." }
        if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
            throw "link.exe not on PATH -- run inside an MSVC dev environment, or use -PatchOnly."
        }
        Write-Host "Re-linking $Lib -> $outSys"
        # Same flags as the CI link step, with product OUT/PDB names.
        & link.exe /OUT:$outSys /RELEASE /DEBUG /NOLOGO /NXCOMPAT `
            /NODEFAULTLIB /SUBSYSTEM:NATIVE /DRIVER /DYNAMICBASE /MANIFEST:NO `
            "/PDBALTPATH:$outPdb" /MACHINE:X64 /OPT:REF,ICF /SUBSYSTEM:NATIVE,6.01 `
            /ENTRY:FxDriverEntry "/MERGE:.edata=.rdata;_TEXT=.text;_PAGE=PAGE" `
            /MERGE:.rustc=.data /INTEGRITYCHECK `
            /LIBPATH:libs/x64 /LIBPATH:c_helper/x64 $Lib
        if ($LASTEXITCODE -ne 0) { throw "link.exe failed ($LASTEXITCODE)." }
    }
    else {
        # ---- Patch mode ---------------------------------------------------------
        if (-not (Test-Path $Sys)) { throw "Missing $Sys." }
        Copy-Item $Sys $outSys -Force
        if (Test-Path $Pdb) { Copy-Item $Pdb $outPdb -Force }

        $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $outSys))

        # Locate the CodeView RSDS record: 'RSDS' + GUID(16) + age(4) + pdbPath\0
        $sig = [System.Text.Encoding]::ASCII.GetBytes("RSDS")
        $rsds = -1
        for ($i = 0; $i -le $bytes.Length - 4; $i++) {
            if ($bytes[$i] -eq $sig[0] -and $bytes[$i+1] -eq $sig[1] -and
                $bytes[$i+2] -eq $sig[2] -and $bytes[$i+3] -eq $sig[3]) { $rsds = $i; break }
        }
        if ($rsds -lt 0) { throw "CodeView RSDS record not found in $outSys." }

        $pathStart = $rsds + 24
        $end = $pathStart
        while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
        $slot = $end - $pathStart            # bytes available (excludes the null)
        $old  = [System.Text.Encoding]::ASCII.GetString($bytes, $pathStart, $slot)

        $newBytes = [System.Text.Encoding]::ASCII.GetBytes($outPdb)   # bare name, no dir
        if ($newBytes.Length -gt $slot) {
            throw ("Embedded PDB name '$old' ($slot bytes) is too short to hold " +
                   "'$outPdb' ($($newBytes.Length) bytes). Re-link instead (drop " +
                   "-PatchOnly), or link the source binary with a longer /PDBALTPATH.")
        }
        Write-Host "Patching embedded PDB path '$old' -> '$outPdb'"
        [Array]::Copy($newBytes, 0, $bytes, $pathStart, $newBytes.Length)
        # Null out the remainder of the old slot.
        for ($j = $pathStart + $newBytes.Length; $j -lt $end; $j++) { $bytes[$j] = 0 }

        # Recompute PE checksum (kernel images are validated at load).
        $len    = $bytes.Length
        $lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
        $csOff  = $lfanew + 24 + 64          # optional header (@+24) + CheckSum (@+64)
        for ($k = 0; $k -lt 4; $k++) { $bytes[$csOff + $k] = 0 }   # zero before summing

        [uint64]$sum = 0
        for ($i = 0; $i -lt $len; $i += 2) {
            $w = [uint32]$bytes[$i]
            if ($i + 1 -lt $len) { $w = $w -bor ([uint32]$bytes[$i + 1] -shl 8) }
            $sum += [uint64]$w
        }
        while ($sum -shr 16) { $sum = ($sum -band 0xffff) + ($sum -shr 16) }
        [uint32]$checksum = ([uint32]$sum) + [uint32]$len
        [Array]::Copy([BitConverter]::GetBytes($checksum), 0, $bytes, $csOff, 4)

        [System.IO.File]::WriteAllBytes((Resolve-Path $outSys), $bytes)
        Write-Host ("Set PE checksum to 0x{0:X8}" -f $checksum)
    }

    if ($Sign) {
        Write-Host "Signing $outSys"
        & signtool sign /a /s PrivateCertStore /n DriverCertificate /fd SHA256 `
            /t http://timestamp.digicert.com $outSys
        if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)." }
    }

    Write-Host "Done -> $outSys$([Environment]::NewLine)"
}
finally {
    Pop-Location
}
