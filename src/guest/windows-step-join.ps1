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
