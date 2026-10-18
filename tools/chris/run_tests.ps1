[CmdletBinding()]
param(
    [string]$Python,
    [switch]$UnitOnly
)

$ErrorActionPreference = 'Stop'
$chrisProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if (-not $Python) { $Python = Join-Path $chrisProjectRoot '.venv-chris\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $Python)) { throw 'Create .venv-chris and install tests/chris/requirements.txt first.' }
$chrisContainer = 'chris-tests-' + [guid]::NewGuid().ToString('N').Substring(0,12)
$chrisContainerCreated = $false
$chrisPreviousDatabaseUrl = $env:CHRIS_TEST_DATABASE_URL
$chrisPreviousPostgresPassword = $env:POSTGRES_PASSWORD
$chrisTestExitCode = 1
Push-Location -LiteralPath $chrisProjectRoot
try {
    New-Item -ItemType Directory -Force -Path '.chris-runtime' | Out-Null
    if ($UnitOnly) {
        & $Python -m pytest tests/chris/test_validation.py tests/chris/test_auth.py tests/chris/test_reports.py tests/chris/test_postman.py -q -p no:cacheprovider
        $chrisTestExitCode = $LASTEXITCODE
    } else {
        $env:POSTGRES_PASSWORD = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
        docker run --detach --rm --name $chrisContainer --env POSTGRES_PASSWORD --env POSTGRES_DB=chris_test --publish 127.0.0.1::5432 postgres:17
        if ($LASTEXITCODE -ne 0) { throw 'Could not start the dedicated PostgreSQL test container.' }
        $chrisContainerCreated = $true
        $chrisDbReady = $false
        for ($chrisAttempt = 0; $chrisAttempt -lt 30; $chrisAttempt++) {
            docker exec $chrisContainer pg_isready --host=127.0.0.1 --username=postgres --dbname=chris_test *> $null
            if ($LASTEXITCODE -eq 0) { $chrisDbReady = $true; break }
            Start-Sleep -Milliseconds 500
        }
        if (-not $chrisDbReady) { throw 'The temporary PostgreSQL server did not become ready.' }
        $chrisPortText = (docker port $chrisContainer 5432/tcp).Trim().Split(':')[-1]
        $chrisPort = 0
        if (-not [int]::TryParse($chrisPortText, [ref]$chrisPort) -or $chrisPort -lt 1 -or $chrisPort -gt 65535) {
            throw 'Docker returned an invalid local port.'
        }
        $env:CHRIS_TEST_DATABASE_URL = "postgresql+psycopg://postgres:$($env:POSTGRES_PASSWORD)@127.0.0.1:$chrisPort/chris_test"
        & $Python -m pytest tests/chris -q -p no:cacheprovider --junitxml=.chris-runtime/latest-tests.xml
        $chrisTestExitCode = $LASTEXITCODE
    }
} finally {
    $env:CHRIS_TEST_DATABASE_URL = $chrisPreviousDatabaseUrl
    $env:POSTGRES_PASSWORD = $chrisPreviousPostgresPassword
    if ($chrisContainerCreated) {
        if ($chrisContainer -notmatch '^chris-tests-[0-9a-f]{12}$') { throw 'Unexpected test container name; refusing cleanup.' }
        docker stop --time 5 $chrisContainer | Out-Null
    }
    Pop-Location
}
exit $chrisTestExitCode
