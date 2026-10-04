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

# @STEPS@
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
