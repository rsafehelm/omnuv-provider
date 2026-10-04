# Omnuv: a Windows machine's first boot, written by the provider agent
# (src/guest_windows.rs) onto the machine's NoCloud drive and run once by
# cloudbase-init's runcmd, as LocalSystem, after its network plugin.
#
# The Windows twin of the Linux install script (instance.rs install_script):
# each step's number and label written to the status file before it runs, and
# `rc=` added once, at the end, whatever happened. The provider reads that one
# file through the guest agent (VM.GuestAgent.FileRead) and nothing wider.
#
# **It prints step names and nothing else.** cloudbase-init writes this
# script's output to its own log at debug level, and its configuration in the
# image has debug on, so a secret printed here would be on the disk. The
# overlay's key is in the tunnel's join file only; the stream login is in its
# own file only.
#
# Exit codes 1001-1003 are cloudbase-init's reboot requests
# (execcmd.get_plugin_return_value); this script exits 0 or 1 and nothing else.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$onv = 'C:\ProgramData\onv'
$status = 'C:\ProgramData\onv\recipe-status'
$utf8 = New-Object System.Text.UTF8Encoding($false)

# SYSTEM and Administrators, by SID: account names are localised.
function Set-OnvPrivate([string] $path, [switch] $directory) {
    $inherit = if ($directory) { '(OI)(CI)' } else { '' }
    & icacls.exe $path /inheritance:r /grant:r "*S-1-5-18:${inherit}F" "*S-1-5-32-544:${inherit}F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls refused $path ($LASTEXITCODE)" }
}

function Write-OnvStatus([string] $text) {
    [System.IO.File]::WriteAllText($status, $text, $utf8)
}

$STEP = 'starting'
$LABEL = ''
$rc = 0
try {
    # Before anything is written under it: the status, the stream login and
    # the steps are SYSTEM's and Administrators', never Users' (ProgramData's
    # default lets Users read). A child with its own protected DACL, as the
    # tunnel's data directory has from the image, keeps it.
    New-Item -ItemType Directory -Force -Path $onv | Out-Null
    Set-OnvPrivate $onv -directory

    $STEP = '1/4'
    $LABEL = 'Starting the machine'
    Write-OnvStatus ("step={0}`nlabel={1}`n" -f $STEP, $LABEL)
    Write-Output "omnuv: step $STEP"
    & {
        # The buyer's public keys (W2): OpenSSH reads an administrator's keys from
        # administrators_authorized_keys, and ignores the file unless SYSTEM and
        # Administrators alone hold it. The drive wrote it (write_files); this makes
        # it count.
        $keys = 'C:\ProgramData\ssh\administrators_authorized_keys'
        if (Test-Path -LiteralPath $keys) { Set-OnvPrivate $keys }
        # sshd, where the image has it: automatic, and reachable from the overlay
        # alone, as the stream is. OpenSSH's own rule admits every address and is
        # turned off.
        $sshd = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
        if ($sshd) {
            Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
            if (-not (Get-NetFirewallRule -Name 'onv-sshd' -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -Name 'onv-sshd' -DisplayName 'Onv SSH (overlay only)' -Direction Inbound `
                    -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress '100.64.0.0/10' | Out-Null
            }
            Set-Service -Name 'sshd' -StartupType Automatic
            Start-Service -Name 'sshd'
        } else {
            Write-Output 'omnuv: this image has no sshd; the keys wait for one'
        }
    }

    $STEP = '2/4'
    $LABEL = 'Joining your private network'
    Write-OnvStatus ("step={0}`nlabel={1}`n" -f $STEP, $LABEL)
    Write-Output "omnuv: step $STEP"
    & {
        # The overlay (W3): the tunnel, in machine mode, spends the join file the drive
        # wrote and removes it, spent or refused (omnuv-client tunnel/machine.go).
        # Waited for, bounded, and never fatal: a machine off its network still boots
        # and still answers, as on Linux (`netbird up ... || true`).
        $tunnel = 'C:\ProgramData\onv\tunnel'
        $join = Join-Path $tunnel 'machine-join.json'
        $record = Join-Path $tunnel 'machine\machine.json'
        $service = Get-Service -Name 'OnvTunnel' -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Output 'omnuv: this image has no OnvTunnel service; the machine is not on its network'
            return
        }
        if ($service.Status -ne 'Running') { Start-Service -Name 'OnvTunnel' }
        # ceiling: five minutes, the Linux install's wait for the internet; unmeasured on Windows
        $looks = 0
        while ($looks -lt 60 -and (Test-Path -LiteralPath $join)) {
            $looks++
            Start-Sleep -Seconds 5
        }
        if (Test-Path -LiteralPath $join) {
            Write-Output 'omnuv: the tunnel has not spent its key after five minutes; it keeps trying'
        } elseif (Test-Path -LiteralPath $record) {
            Write-Output "omnuv: joined the network after $looks look(s)"
        } else {
            Write-Output 'omnuv: the overlay refused the key; the machine is not on its network'
        }
    }

    $STEP = '3/4'
    $LABEL = 'Finishing setup'
    Write-OnvStatus ("step={0}`nlabel={1}`n" -f $STEP, $LABEL)
    Write-Output "omnuv: step $STEP"
    & {
        $file = Join-Path $onv 'recipe-step-1.ps1'
        [System.IO.File]::WriteAllBytes($file, [Convert]::FromBase64String('77u/V3JpdGUtT3V0cHV0ICdhIHJlY2lwZSBzdGVwJw=='))
        & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $file
        if ($LASTEXITCODE -ne 0) { throw "the recipe's step exited $LASTEXITCODE" }
    }

    $STEP = '4/4'
    $LABEL = 'Preparing your stream'
    Write-OnvStatus ("step={0}`nlabel={1}`n" -f $STEP, $LABEL)
    Write-Output "omnuv: step $STEP"
    & {
        # The stream's login, the Windows twin of the Linux recipe's
        # /etc/onv/recipe-stream-credential (omnuv db/recipes/steam-gaming.sh): both
        # halves random, minted here rather than sent down, so no secret is in desired
        # state or on the drive. Sunshine keeps only a salted hash; the plaintext is in
        # one file, SYSTEM's and Administrators', read by the provider through the
        # guest agent and left in place, because Core takes only the first delivery.
        $credential = 'C:\ProgramData\onv\recipe-stream-credential'
        if (Test-Path -LiteralPath $credential) {
            Write-Output 'omnuv: the stream login exists already'
            return
        }
        $sunshine = 'C:\Program Files\Sunshine\sunshine.exe'
        if (-not (Test-Path -LiteralPath $sunshine)) { throw 'this image has no Sunshine' }
        function New-OnvToken([int] $length) {
            $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
            $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $byte = New-Object byte[] 1
            $token = New-Object System.Text.StringBuilder
            while ($token.Length -lt $length) {
                $random.GetBytes($byte)
                # 248 is 4 x 62: every symbol equally likely.
                if ($byte[0] -lt 248) { [void] $token.Append($alphabet[$byte[0] % 62]) }
            }
            $token.ToString()
        }
        $user = 'onv-' + (New-OnvToken 8)
        $password = New-OnvToken 20
        if ($user.Length -ne 12 -or $password.Length -ne 20) { throw 'the stream login came out short' }
        # In argv for the length of the call, as on Linux: --creds takes it no other
        # way. Its output is discarded, never logged. 'Continue' around it: Windows
        # PowerShell turns a redirected native stderr line into a terminating error
        # under 'Stop'.
        $ErrorActionPreference = 'Continue'
        & $sunshine --creds $user $password > $null 2> $null
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($code -ne 0) { throw "sunshine --creds exited $code" }
        # Inherits the onv directory's DACL, set before the first step.
        [System.IO.File]::WriteAllText($credential, ("user={0}`npassword={1}`n" -f $user, $password), $utf8)
        # Sunshine reads its login when it starts.
        if (Get-Service -Name 'SunshineService' -ErrorAction SilentlyContinue) {
            Restart-Service -Name 'SunshineService' -Force
        }
    }

    $STEP = 'finished'
    Write-Output 'omnuv: first boot finished'
} catch {
    $rc = 1
    # The step and the kind of failure, never the exception's text: a failing
    # command line may hold what this script must not print.
    Write-Output ("omnuv: first boot stopped at step {0} ({1})" -f $STEP, $_.Exception.GetType().FullName)
} finally {
    try {
        Write-OnvStatus ("step={0}`nlabel={1}`nrc={2}`n" -f $STEP, $LABEL, $rc)
    } catch {
        $rc = 1
    }
}
exit $rc
