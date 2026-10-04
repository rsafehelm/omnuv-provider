# Runs the agent's Windows first-boot script (the golden drive/first-boot.ps1)
# under pwsh on Linux, against stand-ins for what only Windows has: icacls, the
# service and firewall cmdlets, powershell.exe, and Sunshine. What it proves is
# the script's own logic: the status file written before each step and closed
# with rc= at the end, a failing step stopping the install with its number, and
# **one writer of the stream login: the recipe**. The script never mints one,
# never calls Sunshine, never restarts its service, and leaves the recipe's
# login exactly as the recipe wrote it. What it cannot prove is Windows
# PowerShell 5.1 itself, the DACLs and the services: phase 2's clone.
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
# .NET on Linux takes a backslash as part of a name. Sunshine's path goes to a
# stand-in, so a script that called it would be seen to.
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

# A recipe step, in the drive's encoding: UTF-8 with a BOM, base64.
function Step([string] $code) {
    [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("`u{feff}" + $code))
}
function WithRecipe([string] $code) {
    [regex]::Replace($golden, "FromBase64String\('[^']*'\)", "FromBase64String('$(Step $code)')")
}

function Run([string] $name, [string] $script, [hashtable] $environment) {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("onv-win-$name-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $root | Out-Null
    $sunshine = Join-Path $root 'sunshine.sh'
    # Sunshine's stand-in: records that it was called, and with what.
    Set-Content -LiteralPath $sunshine -Value "#!/bin/sh`nprintf '%s %s %s\n' `"`$1`" `"`$2`" `"`$3`" >> '$root/sunshine-got'`n"
    & chmod +x $sunshine
    $body = Rehome $script $root $sunshine
    Set-Content -LiteralPath (Join-Path $root 'run.ps1') -Value ($stubs + "`n" + $body)
    $env:ONV_EVENTS = Join-Path $root 'events'
    $env:ONV_TUNNEL = '0'
    $env:ONV_ROOT = $root
    foreach ($k in $environment.Keys) { Set-Item -Path "env:$k" -Value $environment[$k] }
    $out = & pwsh -NoLogo -NoProfile -NonInteractive -File (Join-Path $root 'run.ps1') 2>&1 | Out-String
    [pscustomobject] @{ Root = $root; Code = $LASTEXITCODE; Out = $out
        Status = Get-Content -Raw -LiteralPath "$root/ProgramData/onv/recipe-status" -ErrorAction SilentlyContinue
        Credential = Get-Content -Raw -LiteralPath "$root/ProgramData/onv/recipe-stream-credential" -ErrorAction SilentlyContinue
        Sunshine = Test-Path -LiteralPath "$root/sunshine-got"
        Restarted = (Test-Path -LiteralPath "$root/events") -and ((Get-Content -Raw -LiteralPath "$root/events") -match 'Sunshine') }
}

# 1. Every step runs, and first boot mints nothing: no login file, Sunshine
#    never called, its service never restarted.
$r = Run 'ok' $golden @{}
Check ($r.Code -eq 0) "a clean first boot exits 0 (got $($r.Code)): $($r.Out)"
Check ($r.Status -eq "step=finished`nlabel=Finishing setup`nrc=0`n") "the status closes finished, rc=0: [$($r.Status)]"
Check ($r.Out.Contains('a recipe step')) "the recipe's own step ran: $($r.Out)"
Check ($null -eq $r.Credential) "first boot wrote no stream login: [$($r.Credential)]"
Check (-not $r.Sunshine) 'first boot never called Sunshine'
Check (-not $r.Restarted) "first boot never restarted Sunshine's service"

# 2. The recipe is the one writer: the login it writes is the login left,
#    byte for byte, and nothing else told Sunshine a login.
$login = "user=onv-recipe01`npassword=RecipeMintedThis0123`n"
$write = "`$f = Join-Path `$env:ONV_ROOT 'ProgramData/onv/recipe-stream-credential'; " +
    "[System.IO.File]::WriteAllText(`$f, `"$($login.Replace("`n", '`n'))`")"
$w = Run 'recipe' (WithRecipe $write) @{}
Check ($w.Code -eq 0) "a recipe that writes its login exits 0 (got $($w.Code)): $($w.Out)"
Check ($w.Credential -eq $login) "the login left is the recipe's, unchanged: [$($w.Credential)]"
Check (-not $w.Sunshine) 'and Sunshine was told no other'
Check (-not $w.Out.Contains('RecipeMintedThis0123')) 'the password is not on the output cloudbase-init logs'

# 3. A recipe step that fails stops the install at its number.
$f = Run 'fail' (WithRecipe 'exit 3') @{}
Check ($f.Code -eq 1) "a failed step exits 1 (got $($f.Code))"
Check ($f.Status -eq "step=3/3`nlabel=Finishing setup`nrc=1`n") "the status names the step that failed: [$($f.Status)]"
Check ($null -eq $f.Credential) 'no login after a failed install'
Check ($f.Out.Contains('stopped at step 3/3')) "the output names the step: $($f.Out)"

# 4. The tunnel spends the join file: the wait ends on its answer.
$t = Run 'tunnel' $golden @{ ONV_TUNNEL = '1' }
Check ($t.Code -eq 0 -and $t.Out.Contains('refused the key')) "with no join file and no record, the key reads as refused: $($t.Out)"

if ($failures -ne 0) { Write-Output "$failures check(s) failed"; exit 1 }
Write-Output 'all checks passed'
