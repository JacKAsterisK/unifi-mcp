param(
    [Parameter(Mandatory=$true)][string]$ProfileDirectory,
    [switch]$PassThru,
    [switch]$ExplainFailure
)
$ErrorActionPreference = 'Stop'
# Use inbox Windows PowerShell modules even when launched from PowerShell 7.
$env:PSModulePath = $PSHOME + '\Modules'
$valid = & {
    $itemLabel = 'Windows account'
    $operation = 'read identity'
    try {
        $accountSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $allowedSids = @($accountSid, 'S-1-5-18')
        foreach ($itemPath in @($ProfileDirectory, (Join-Path $ProfileDirectory 'settings.json'), (Join-Path $ProfileDirectory 'credential.dpapi'))) {
            $itemLabel = if ($itemPath -eq $ProfileDirectory) { 'profile directory' } else { [IO.Path]::GetFileName($itemPath) }
            $operation = 'read file metadata'
            $item = Get-Item -LiteralPath $itemPath -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                if ($ExplainFailure) { Write-Warning ('Private profile check: {0} is a link.' -f $itemLabel) }
                return $false
            }
            $operation = 'read ACL'
            $acl = Get-Acl -LiteralPath $itemPath
            $operation = 'read owner'
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowedSids) {
                if ($ExplainFailure) { Write-Warning ('Private profile check: {0} has a different owner.' -f $itemLabel) }
                return $false
            }
            $operation = 'read permission entries'
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowedSids) {
                    if ($ExplainFailure) { Write-Warning ('Private profile check: {0} grants access to another account or group.' -f $itemLabel) }
                    return $false
                }
            }
        }
        return $true
    } catch {
        if ($ExplainFailure) { Write-Warning ('Private profile check: cannot {0} for {1} ({2}).' -f $operation, $itemLabel, $_.Exception.GetType().Name) }
        return $false
    }
}
# Setup shares these exact checks without starting another PowerShell process.
# The standalone launcher still receives the original fail-closed exit status.
if ($PassThru) { return [bool]$valid }
if ($valid) { exit 0 }
exit 1
