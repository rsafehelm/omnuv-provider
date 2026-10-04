# Runs the agent's Windows first-boot script (the golden drive/first-boot.ps1)
# under pwsh on Linux, against stand-ins for what only Windows has: icacls, the
# service and firewall cmdlets, powershell.exe, and Sunshine. What it proves is
# the script's own logic: the status file written before each step and closed
# with rc= at the end, a failing step stopping the install with its number,
# the stream login minted once, written whole, and given to Sunshine as
# written, and nothing secret on the script's output. What it cannot prove is
# Windows PowerShell 5.1 itself, the DACLs and the services: phase 2's clone.
#
#     pwsh tests/windows/harness.ps1      (packaging/check.sh runs it in a pinned image)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$golden = Get-Content -Raw -LiteralPath (Join-Path $here 'drive/first-boot.ps1')
$failures = 0
function Check([bool] $ok, [string] $what) {
    if ($ok) { Write-Output "ok    $what" } else { Write-Output "FAIL  $what"; $script:failures++ }
}

# Every `C:\…` literal moved under a scratch root, with `/` for `\`, since
# .NET on Linux takes a backslash as part of a name.
function Rehome([string] $text, [string] $root, [string] $sunshine) {
    $text = $text.Replace("'C:\Program Files\Sunshine\sunshine.exe'", "'$sunshine'")
    $text = $text.Replace("'machine\machine.json'", "'machine/machine.json'")
    [regex]::Replace($text, "'C:\\([^']*)'", { param($m) "'" + $root + '/' + $m.Groups[1].Value.Replace('\', '/') + "'" })
}

$stubs = @'
function icacls.exe { $global:LASTEXITCODE = 0 }
function Get-Service {
    $Name = $args[[array]::IndexOf($args, '-Name') + 1]
    if ($Name -eq 'OnvTunnel' -and $env:ONV_TUNNEL -eq '1') { return [pscustomobject] @{ Name = $Name; Status = 'Running' } }
    if ($Name -eq 'SunshineService') { return [pscustomobject] @{ Name = $Name; Status = 'Running' } }
    $null
}
function Restart-Service { Add-Content -LiteralPath $env:ONV_EVENTS -Value "restart $args" }
function Start-Service { Add-Content -LiteralPath $env:ONV_EVENTS -Value "start $args" }
function powershell.exe { & pwsh @args; $global:LASTEXITCODE = $LASTEXITCODE }
'@

function Run([string] $name, [string] $script, [hashtable] $environment) {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("onv-win-$name-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $root | Out-Null
    $sunshine = Join-Path $root 'sunshine.sh'
    # Sunshine's stand-in: records the login it was given.
    Set-Content -LiteralPath $sunshine -Value "#!/bin/sh`nprintf '%s %s %s\n' `"`$1`" `"`$2`" `"`$3`" > '$root/sunshine-got'`n"
    & chmod +x $sunshine
    $body = Rehome $script $root $sunshine
    Set-Content -LiteralPath (Join-Path $root 'run.ps1') -Value ($stubs + "`n" + $body)
    $env:ONV_EVENTS = Join-Path $root 'events'
    $env:ONV_TUNNEL = '0'
    foreach ($k in $environment.Keys) { Set-Item -Path "env:$k" -Value $environment[$k] }
    $out = & pwsh -NoLogo -NoProfile -NonInteractive -File (Join-Path $root 'run.ps1') 2>&1 | Out-String
    [pscustomobject] @{ Root = $root; Code = $LASTEXITCODE; Out = $out
        Status = Get-Content -Raw -LiteralPath "$root/ProgramData/onv/recipe-status" -ErrorAction SilentlyContinue }
}

# 1. Every step runs; the login is minted, written whole, and is what Sunshine got.
$r = Run 'ok' $golden @{}
Check ($r.Code -eq 0) "a clean first boot exits 0 (got $($r.Code)): $($r.Out)"
Check ($r.Status -eq "step=finished`nlabel=Preparing your stream`nrc=0`n") "the status closes finished, rc=0: [$($r.Status)]"
$cred = Get-Content -Raw -LiteralPath "$($r.Root)/ProgramData/onv/recipe-stream-credential" -ErrorAction SilentlyContinue
Check ($cred -match "^user=(onv-[A-Za-z0-9]{8})`npassword=([A-Za-z0-9]{20})`n$") "the login is user=onv-<8>, password=<20>: [$cred]"
$user = $Matches[1]; $password = $Matches[2]
$got = (Get-Content -Raw -LiteralPath "$($r.Root)/sunshine-got" -ErrorAction SilentlyContinue)
Check ($got -eq "--creds $user $password`n") "Sunshine was given the same login: [$got]"
Check (-not $r.Out.Contains($password)) 'the password is not on the output cloudbase-init logs'
Check ($r.Out.Contains('a recipe step')) "the recipe's own step ran: $($r.Out)"
Check ((Get-Content -Raw -LiteralPath "$($r.Root)/events") -match 'restart') 'Sunshine was restarted to read its login'

# 2. Again, on the same disk: the login is not minted twice.
$again = Rehome $golden $r.Root (Join-Path $r.Root 'sunshine.sh')
Set-Content -LiteralPath (Join-Path $r.Root 'run2.ps1') -Value ($stubs + "`n" + $again)
& pwsh -NoLogo -NoProfile -NonInteractive -File (Join-Path $r.Root 'run2.ps1') | Out-Null
$cred2 = Get-Content -Raw -LiteralPath "$($r.Root)/ProgramData/onv/recipe-stream-credential"
Check ($cred2 -eq $cred) 'a second run keeps the first login'

# 3. A recipe step that fails stops the install at its number, with no login.
$failing = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("`u{feff}exit 3"))
$broken = [regex]::Replace($golden, "FromBase64String\('[^']*'\)", "FromBase64String('$failing')")
Check ($broken -ne $golden) 'the failing step was put in'
$f = Run 'fail' $broken @{}
Check ($f.Code -eq 1) "a failed step exits 1 (got $($f.Code))"
Check ($f.Status -eq "step=3/4`nlabel=Finishing setup`nrc=1`n") "the status names the step that failed: [$($f.Status)]"
Check (-not (Test-Path -LiteralPath "$($f.Root)/ProgramData/onv/recipe-stream-credential")) 'no login after a failed install'
Check ($f.Out.Contains('stopped at step 3/4')) "the output names the step: $($f.Out)"

# 4. The tunnel spends the join file: the wait ends on its answer.
$t = Run 'tunnel' $golden @{ ONV_TUNNEL = '1' }
Check ($t.Code -eq 0 -and $t.Out.Contains('refused the key')) "with no join file and no record, the key reads as refused: $($t.Out)"

# 5. Without Sunshine the stream step fails, and says so by step.
$n = Run 'nosunshine' ($golden.Replace("'C:\Program Files\Sunshine\sunshine.exe'", "'C:\nowhere\sunshine.exe'")) @{}
Check ($n.Code -eq 1 -and $n.Status -eq "step=4/4`nlabel=Preparing your stream`nrc=1`n") "no Sunshine stops at the stream: [$($n.Status)]"

if ($failures -ne 0) { Write-Output "$failures check(s) failed"; exit 1 }
Write-Output 'all checks passed'
