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
# overlay's key is in the tunnel's join file only. The stream login is the
# recipe's: it mints it and writes it, and this script never does.
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
    # Before anything is written under it: the status, the recipe's stream
    # login and the steps are SYSTEM's and Administrators', never Users' (ProgramData's
    # default lets Users read). A child with its own protected DACL, as the
    # tunnel's data directory has from the image, keeps it.
    New-Item -ItemType Directory -Force -Path $onv | Out-Null
    Set-OnvPrivate $onv -directory

    $STEP = '1/3'
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

    $STEP = '2/3'
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

    $STEP = '3/3'
    $LABEL = 'Finishing setup'
    Write-OnvStatus ("step={0}`nlabel={1}`n" -f $STEP, $LABEL)
    Write-Output "omnuv: step $STEP"
    & {
        $file = Join-Path $onv 'recipe-step-1.ps1'
        [System.IO.File]::WriteAllBytes($file, [Convert]::FromBase64String('77u/V3JpdGUtT3V0cHV0ICdhIHJlY2lwZSBzdGVwJw=='))
        & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $file
        if ($LASTEXITCODE -ne 0) { throw "the recipe's step exited $LASTEXITCODE" }
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
