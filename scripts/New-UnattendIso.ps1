# Builds .lab\unattend.iso with autounattend.xml at the root. Windows Setup
# reads that file from any attached DVD. New-LabVm.ps1 attaches this as a
# second drive; boot order stays on the Windows ISO.

param(
    [string]$XmlPath,
    [string]$IsoPath
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $XmlPath) { $XmlPath = Join-Path $Root "unattend\autounattend.xml" }
if (-not $IsoPath) { $IsoPath = Join-Path $Root ".lab\unattend.iso" }
if (-not (Test-Path $XmlPath)) { throw "Missing $XmlPath" }

$stage = Join-Path $env:TEMP "iis-id-unattend"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item $XmlPath (Join-Path $stage "autounattend.xml")
New-Item -ItemType Directory -Force -Path (Split-Path $IsoPath) | Out-Null

if (-not ("ISOFile" -as [type])) {
    $cp = New-Object System.CodeDom.Compiler.CompilerParameters
    $cp.CompilerOptions = "/unsafe"
    Add-Type -CompilerParameters $cp -TypeDefinition @"
public class ISOFile {
  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks) {
    int bytes = 0;
    byte[] buf = new byte[BlockSize];
    var ptr = (System.IntPtr)(&bytes);
    var o = System.IO.File.OpenWrite(Path);
    var i = Stream as System.Runtime.InteropServices.ComTypes.IStream;
    if (o != null) {
      while (TotalBlocks-- > 0) {
        i.Read(buf, BlockSize, ptr);
        o.Write(buf, 0, bytes);
      }
      o.Flush(); o.Close();
    }
  }
}
"@
}

$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.FileSystemsToCreate = 3
$fsi.VolumeName = "UNATTEND"
$fsi.Root.AddTree($stage, $false)
$result = $fsi.CreateResultImage()
if (Test-Path $IsoPath) { Remove-Item $IsoPath -Force }
[ISOFile]::Create($IsoPath, $result.ImageStream, $result.BlockSize, $result.TotalBlocks)
Remove-Item $stage -Recurse -Force
Write-Host "unattend ISO: $IsoPath"
