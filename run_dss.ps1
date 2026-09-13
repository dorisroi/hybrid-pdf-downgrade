# run_dss.ps1 -- independent validation with the EU DSS reference implementation.
#
# Kept out of run_all.py on purpose: that pipeline is pure Python and must stay
# runnable without a JDK. This step needs Java 17 and the DSS 6.5 jars. It reads
# the artifacts run_all.py produced and writes results/dss_rule.json, which
# run_all.py picks up on its next run to emit the DSS macros for the paper.
#
#   1.  python run_all.py      (produces results/artifacts/)
#   2.  .\run_dss.ps1          (produces results/dss_rule.json)
#   3.  python run_all.py      (folds the DSS figures into numbers.tex)

# NOT "Stop": in Windows PowerShell 5.1 a native program writing to stderr
# surfaces as an ErrorRecord, and SLF4J always greets us there. Exit codes are
# checked explicitly instead.
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

$jdk = (Get-Command java -ErrorAction SilentlyContinue)
if (-not $jdk) { throw "java not found on PATH; DSS validation needs JDK 17+" }
$jdkBin = Split-Path $jdk.Source

$m2 = "$env:USERPROFILE\.m2\repository"
if (-not (Test-Path $m2)) { throw "no Maven repository at $m2; run 'mvn -f dssval/pom.xml dependency:go-offline' once" }

# DSS 6.5 only, and one BouncyCastle. Older copies of either on the classpath
# produce NoSuchMethodError deep inside certificate parsing.
$jars = Get-ChildItem $m2 -Recurse -Filter "*.jar" |
    Where-Object {
        $_.Name -notmatch "sources|javadoc" -and
        $_.FullName -notmatch "\\6\.2\\" -and
        -not ($_.FullName -match "bouncycastle" -and $_.FullName -notmatch "\\1\.85\\")
    } | ForEach-Object { $_.FullName.Replace('\', '/') }

Write-Host "classpath: $($jars.Count) jars"
$cp = $jars -join ';'

# javac/java argfiles treat backslash as an escape, hence the forward slashes
New-Item -ItemType Directory -Force -Path dssval\target\classes | Out-Null
Set-Content -Path dssval\cp.txt -Value ('-cp "' + $cp + '"') -Encoding ascii
@(
    '-Dorg.slf4j.simpleLogger.defaultLogLevel=error'
    ('-cp "target/classes;' + $cp + '"')
) | Set-Content -Path dssval\cprun.txt -Encoding ascii

Push-Location dssval
try {
    & "$jdkBin\javac.exe" "@cp.txt" -d target\classes -encoding UTF-8 `
        src\main\java\vn\nckh\DssRule.java
    if ($LASTEXITCODE -ne 0) { throw "javac failed" }

    Remove-Item -Force -ErrorAction SilentlyContinue ..\results\dss_rule.json

    # no 2>&1 here: stderr is already surfaced, and redirecting it would wrap
    # every SLF4J line in an ErrorRecord
    & "$jdkBin\java.exe" "@cprun.txt" vn.nckh.DssRule "../results/artifacts" |
        Where-Object { $_ -notmatch "SLF4J|Standard Commons Logging" } |
        Tee-Object -FilePath ..\results\dss_rule_report.txt
    if ($LASTEXITCODE -ne 0) { Write-Warning "DssRule exited $LASTEXITCODE" }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "report -> results\dss_rule_report.txt"
Write-Host "figures -> results\dss_rule.json   (re-run run_all.py to fold into the paper)"
