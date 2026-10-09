param(
    [Parameter(Mandatory=$true)][string]$ProfileDirectory,
    [switch]$PassThru
)
$ErrorActionPreference = 'Stop'
# Use inbox Windows PowerShell modules even when launched from PowerShell 7.
$env:PSModulePath = $PSHOME + '\Modules'
$valid = & {
    try {
        $accountSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $allowedSids = @($accountSid, 'S-1-5-18')
        foreach ($itemPath in @($ProfileDirectory, (Join-Path $ProfileDirectory 'settings.json'), (Join-Path $ProfileDirectory 'credential.dpapi'))) {
            $item = Get-Item -LiteralPath $itemPath -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
            $acl = Get-Acl -LiteralPath $itemPath
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowedSids) { return $false }
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowedSids) { return $false }
            }
        }
        return $true
    } catch { return $false }
}
# Setup shares these exact checks without starting another PowerShell process.
# The standalone launcher still receives the original fail-closed exit status.
if ($PassThru) { return [bool]$valid }
if ($valid) { exit 0 }
exit 1
