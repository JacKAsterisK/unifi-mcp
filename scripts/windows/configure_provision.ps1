param(
    [string]$ControllerHost,
    [int]$ControllerPort = 443,
    [string]$ProfileDirectory = (Join-Path $env:LOCALAPPDATA 'UniFiMCP\provision'),
    [string]$TrustedTlsSha256,
    [ValidateRange(1,8)][int]$LifetimeHours = 2,
    [switch]$IncludeApiKey,
    [switch]$ReuseReadOnlyLogin
)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = $PSHOME + '\Modules'
Add-Type -AssemblyName System.Security
$repoDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$profilePath = [IO.Path]::GetFullPath($ProfileDirectory)
$readonlyPath = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'UniFiMCP\readonly'))
if ($profilePath.Equals($readonlyPath, [StringComparison]::OrdinalIgnoreCase) -or $profilePath.Equals($repoDirectory, [StringComparison]::OrdinalIgnoreCase) -or $profilePath.StartsWith($repoDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Use a separate private provisioning directory outside the repository.' }
if (-not $ControllerHost) { $ControllerHost = Read-Host 'Local UniFi controller hostname or IP' }
if ($ControllerHost -notmatch '^[A-Za-z0-9._-]+$' -or $ControllerPort -lt 1 -or $ControllerPort -gt 65535) { throw 'Invalid controller address or port.' }
if (-not $TrustedTlsSha256) { $TrustedTlsSha256 = Read-Host 'SHA-256 certificate fingerprint independently confirmed in gateway certificate details' }
$pin = $TrustedTlsSha256.Replace(':', '')
if ($pin -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Enter the 64-digit SHA-256 certificate fingerprint.' }
if (Test-Path -LiteralPath $profilePath) {
    if ((Get-Item -LiteralPath $profilePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Profile cannot be a link.' }
    foreach ($fileName in @('settings.json','credential.dpapi','codex-config.toml')) {
        $existing = Join-Path $profilePath $fileName
        if ((Test-Path -LiteralPath $existing) -and ((Get-Item -LiteralPath $existing -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Profile files cannot be links.' }
    }
    $existingSettings = Join-Path $profilePath 'settings.json'
    if (-not (Test-Path -LiteralPath $existingSettings) -or (Get-Content -LiteralPath $existingSettings -Raw | ConvertFrom-Json).profile_kind -cne 'provision') { throw 'Refusing to overwrite a different credential profile.' }
}
$credential = $null
if ($ReuseReadOnlyLogin) {
    $checker = Join-Path $env:SYSTEMROOT 'System32\WindowsPowerShell\v1.0\powershell.exe'
    & $checker -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'verify_private_profile.ps1') $readonlyPath
    if ($LASTEXITCODE -ne 0) { throw 'Existing login profile is missing or has unsafe permissions.' }
    $sourceBytes = $null
    $sourceLogin = $null
    try {
        $sourceSettings = Get-Content -LiteralPath (Join-Path $readonlyPath 'settings.json') -Raw | ConvertFrom-Json
        if ($sourceSettings.host -cne $ControllerHost -or $sourceSettings.port -ne $ControllerPort -or $sourceSettings.tls_sha256.Replace(':','') -ine $pin -or $sourceSettings.site -cne 'default') { throw 'Profile targets differ.' }
        $encryptedLogin = [Convert]::FromBase64String([IO.File]::ReadAllText((Join-Path $readonlyPath 'credential.dpapi')))
        $sourceBytes = [Security.Cryptography.ProtectedData]::Unprotect($encryptedLogin, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $sourceLogin = [Text.Encoding]::UTF8.GetString($sourceBytes) | ConvertFrom-Json
        if (-not ($sourceLogin.username -is [string]) -or -not $sourceLogin.username -or -not ($sourceLogin.password -is [string]) -or -not $sourceLogin.password) { throw 'Incomplete login.' }
        $credential = [PSCredential]::new($sourceLogin.username, (ConvertTo-SecureString $sourceLogin.password -AsPlainText -Force))
    } catch { throw 'Could not reuse the encrypted login. Check the Windows user, controller and certificate pin.' }
    finally {
        if ($sourceBytes) { [Array]::Clear($sourceBytes, 0, $sourceBytes.Length) }
        $sourceLogin = $null
    }
} else {
    $credential = Get-Credential -Message 'Local UniFi account with Network write access for reviewed provisioning'
}
if (-not $credential) { throw 'No credential entered.' }
$apiSecret = $null
if ($IncludeApiKey) { $apiSecret = Read-Host 'Network Integration API key (needed for firewall zone CRUD and ordering)' -AsSecureString }
$accountSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
[IO.Directory]::CreateDirectory($profilePath) | Out-Null
$directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
$directoryAcl.SetOwner($accountSid)
$directoryAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($accountSid, $systemSid)) { $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')) }
[IO.Directory]::SetAccessControl($profilePath, $directoryAcl)
$utf8 = [Text.UTF8Encoding]::new($false)
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
$apiPointer = [IntPtr]::Zero
$clearBytes = $null
try {
    $values = @{username=$credential.UserName; password=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)}
    if ($apiSecret) {
        $apiPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($apiSecret)
        $values.api_key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($apiPointer)
        if (-not $values.api_key -or $values.api_key -match '\s') { throw 'Invalid API key.' }
    }
    $payload = $values | ConvertTo-Json -Compress
    $clearBytes = $utf8.GetBytes($payload)
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($clearBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllText((Join-Path $profilePath 'credential.dpapi'), [Convert]::ToBase64String($encrypted), $utf8)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    if ($apiPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($apiPointer) }
    if ($clearBytes) { [Array]::Clear($clearBytes, 0, $clearBytes.Length) }
    $values = $null
    $payload = $null
}
$settings = @{profile_kind='provision'; host=$ControllerHost; port=$ControllerPort; site='default'; tls_sha256=$pin; expires_at=[DateTimeOffset]::UtcNow.AddHours($LifetimeHours).ToString('o')} | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $profilePath 'settings.json'), $settings, $utf8)
$fileAcl = [Security.AccessControl.FileSecurity]::new()
$fileAcl.SetOwner($accountSid)
$fileAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($accountSid,$systemSid)) { $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow')) }
foreach ($fileName in @('credential.dpapi','settings.json')) { [IO.File]::SetAccessControl((Join-Path $profilePath $fileName), $fileAcl) }
$pythonPath = Join-Path $repoDirectory '.venv\Scripts\python.exe'
$configLines = & $pythonPath (Join-Path $PSScriptRoot 'provision_launcher.py') --profile $profilePath --print-config
if ($LASTEXITCODE -ne 0) { throw 'Could not generate the Codex configuration.' }
[IO.File]::WriteAllText((Join-Path $profilePath 'codex-config.toml'), ($configLines -join "`n") + "`n", $utf8)
[IO.File]::SetAccessControl((Join-Path $profilePath 'codex-config.toml'), $fileAcl)
Write-Host ('Provisioning profile saved; MCP entry is disabled by default: ' + (Join-Path $profilePath 'codex-config.toml'))
Write-Host 'No gateway connection was made. Enable only for reviewed changes; revoke the account/API key afterward.'
