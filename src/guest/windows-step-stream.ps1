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
