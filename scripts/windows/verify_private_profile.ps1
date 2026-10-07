param([Parameter(Mandatory=$true)][string]$ProfileDirectory)
$ErrorActionPreference = 'Stop'
# Use inbox Windows PowerShell modules even when launched from PowerShell 7.
$env:PSModulePath = $PSHOME + '\Modules'
try {
    $accountSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowedSids = @($accountSid, 'S-1-5-18')
    foreach ($itemPath in @($ProfileDirectory, (Join-Path $ProfileDirectory 'settings.json'), (Join-Path $ProfileDirectory 'credential.dpapi'))) {
        $item = Get-Item -LiteralPath $itemPath -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 1 }
        $acl = Get-Acl -LiteralPath $itemPath
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowedSids) { exit 1 }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowedSids) { exit 1 }
        }
    }
    exit 0
} catch { exit 1 }
