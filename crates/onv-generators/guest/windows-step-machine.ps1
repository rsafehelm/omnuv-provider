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
