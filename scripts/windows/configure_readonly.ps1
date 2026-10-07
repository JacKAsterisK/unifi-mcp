param(
    [string]$ControllerHost = '192.168.1.1',
    [int]$ControllerPort = 443,
    [string]$ProfileDirectory = (Join-Path $env:LOCALAPPDATA 'UniFiMCP\readonly'),
    [string]$Username,
    [string]$PasswordFile,
    [string]$TrustedTlsSha256,
    [switch]$ViewOnlyConfirmed,
    [switch]$CredentialOnly,
    [switch]$UseStoredCredential
)
$ErrorActionPreference = 'Stop'
# Use inbox Windows PowerShell modules even when launched from PowerShell 7.
$env:PSModulePath = $PSHOME + '\Modules'
Add-Type -AssemblyName System.Security
$repoDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$profilePath = [IO.Path]::GetFullPath($ProfileDirectory)
if ($profilePath.Equals($repoDirectory, [StringComparison]::OrdinalIgnoreCase) -or $profilePath.StartsWith($repoDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Keep this credential profile outside the repository.'
}
if (-not $ViewOnlyConfirmed) {
    $role = Read-Host 'Confirm this is a dedicated Network View Only account (type VIEW ONLY)'
    if ($role -cne 'VIEW ONLY') { throw 'Create the dedicated View Only account first.' }
}
if ($CredentialOnly -and (Test-Path -LiteralPath (Join-Path $profilePath 'settings.json'))) { throw 'This profile is already configured; rotate with a confirmed pin.' }
$pin = $null
if (-not $CredentialOnly) {
    if (-not $TrustedTlsSha256) { $TrustedTlsSha256 = Read-Host 'SHA-256 certificate fingerprint independently confirmed in the gateway certificate details' }
    $pin = $TrustedTlsSha256.Replace(':', '')
    if ($pin -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Enter the 64-digit SHA-256 fingerprint.' }
}
if ($UseStoredCredential) {
    if ($CredentialOnly -or $PasswordFile -or -not (Test-Path -LiteralPath (Join-Path $profilePath 'credential.dpapi'))) { throw 'No staged credential is available.' }
} elseif ($PasswordFile) {
    if (-not $Username) { throw 'Username is required when importing a password file.' }
    if ((Get-Item -LiteralPath $PasswordFile).Length -gt 65536) { throw 'Password source is too large.' }
    $sourcePassword = [IO.File]::ReadAllText($PasswordFile).TrimEnd([char[]]"`r`n")
    if (-not $sourcePassword) { throw 'Password source is empty.' }
    $credential = [PSCredential]::new($Username, (ConvertTo-SecureString $sourcePassword -AsPlainText -Force))
    $sourcePassword = $null
} else {
    $credential = Get-Credential -Message 'Dedicated local UniFi Network View Only account'
    if (-not $credential) { throw 'No credential entered.' }
}
$accountSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
if (Test-Path -LiteralPath $profilePath) {
    if ((Get-Item -LiteralPath $profilePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Profile cannot be a link.' }
    foreach ($fileName in @('settings.json','credential.dpapi','codex-config.toml')) {
        $existing = Join-Path $profilePath $fileName
        if ((Test-Path -LiteralPath $existing) -and ((Get-Item -LiteralPath $existing -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Profile files cannot be links.' }
    }
} else { [IO.Directory]::CreateDirectory($profilePath) | Out-Null }
$directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
$directoryAcl.SetOwner($accountSid)
$directoryAcl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($accountSid, $systemSid)) {
    $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
}
[IO.Directory]::SetAccessControl($profilePath, $directoryAcl)
$utf8 = [Text.UTF8Encoding]::new($false)
if (-not $UseStoredCredential) {
$secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
$clearBytes = $null
try {
    $payload = @{username=$credential.UserName; password=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer)} | ConvertTo-Json -Compress
    $clearBytes = $utf8.GetBytes($payload)
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($clearBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllText((Join-Path $profilePath 'credential.dpapi'), [Convert]::ToBase64String($encrypted), $utf8)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer)
    if ($clearBytes) { [Array]::Clear($clearBytes, 0, $clearBytes.Length) }
    $payload = $null
}
}
if ($CredentialOnly) {
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetOwner($accountSid)
    $fileAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($accountSid,$systemSid)) { $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow')) }
    [IO.File]::SetAccessControl((Join-Path $profilePath 'credential.dpapi'), $fileAcl)
    Write-Host 'Credential encrypted and staged. No authenticated connection or MCP configuration was created.'
    exit 0
}
$settings = @{host=$ControllerHost; port=$ControllerPort; site='default'; tls_sha256=$pin} | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $profilePath 'settings.json'), $settings, $utf8)
# Reset file ACLs even when rotating an existing profile.
foreach ($fileName in @('credential.dpapi','settings.json')) {
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetOwner($accountSid)
    $fileAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($accountSid,$systemSid)) { $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow')) }
    [IO.File]::SetAccessControl((Join-Path $profilePath $fileName), $fileAcl)
}
$pythonPath = Join-Path $repoDirectory '.venv\Scripts\python.exe'
$configLines = & $pythonPath (Join-Path $PSScriptRoot 'readonly_launcher.py') --profile $profilePath --print-config
if ($LASTEXITCODE -ne 0) { throw 'Could not generate the Codex configuration.' }
[IO.File]::WriteAllText((Join-Path $profilePath 'codex-config.toml'), ($configLines -join "`n") + "`n", $utf8)
[IO.File]::SetAccessControl((Join-Path $profilePath 'codex-config.toml'), $fileAcl)
Write-Host ('Profile saved. Add the MCP entry from: ' + (Join-Path $profilePath 'codex-config.toml'))
