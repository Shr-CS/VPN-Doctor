param([switch]$Test)

$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $compiler)) {
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
if (-not (Test-Path $compiler)) {
    throw 'The .NET Framework 4 C# compiler was not found. Run this script on Windows with .NET Framework 4.x installed.'
}

$outputDir = Join-Path $PSScriptRoot 'build'
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$exe = Join-Path $outputDir 'VPNDoctor.exe'
& $compiler /nologo /target:winexe /codepage:65001 "/out:$exe" (Join-Path $PSScriptRoot 'OpenVPNDoctor.cs') /r:System.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll
if ($LASTEXITCODE -ne 0) { throw 'C# compilation failed.' }

if ($Test) {
    $process = Start-Process -FilePath $exe -ArgumentList '--selftest' -Wait -PassThru
    $result = Join-Path $outputDir 'selftest_result.txt'
    if (Test-Path $result) { Get-Content $result -Encoding UTF8 }
    if ($process.ExitCode -ne 0) { throw "Self-test failed with exit code $($process.ExitCode)." }
    if (-not (Test-Path $result)) { throw 'Self-test did not produce a result file.' }
}

Write-Output "Built $exe"
