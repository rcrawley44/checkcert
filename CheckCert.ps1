# ===== Config =====
$WarningDays = 30
$Now = Get-Date

# ===== Get certificates =====
$ExpiringCerts = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        $_.NotAfter -lt $Now.AddDays($WarningDays)
    } |
    Select-Object Subject,
        Thumbprint,
        NotAfter,
        @{
            Name = "DaysRemaining"
            Expression = {
                ($_.NotAfter - $Now).Days
            }
        }

# ===== Output and exit codes =====
if ($ExpiringCerts.Count -eq 0) {
    Write-Output "OK: No SSL certificates expiring within $WarningDays days."
    exit 0
}
else {
    Write-Output "WARNING: SSL certificates expiring within $WarningDays days:"
    Write-Output "------------------------------------------------------------"

    foreach ($cert in $ExpiringCerts) {
        Write-Output "Subject: $($cert.Subject)"
        Write-Output "Expires: $($cert.NotAfter)"
        Write-Output "Days Remaining: $($cert.DaysRemaining)"
        Write-Output "Thumbprint: $($cert.Thumbprint)"
        Write-Output "------------------------------------------------------------"
    }

    exit 1
}