# ===== Config =====
$WarningDays = 30
$Now = Get-Date

# ===== Helper functions =====

function Get-EkuKey {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # Create a consistent, comparable list of EKU object identifiers.
    # Certificates without an EKU extension will return an empty string.
    return (
        $Certificate.EnhancedKeyUsageList |
            ForEach-Object { $_.ObjectId.Value } |
            Sort-Object
    ) -join ","
}

function Find-ReplacementCertificate {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [array]$AllCertificates
    )

    $CertificateEku = Get-EkuKey -Certificate $Certificate

    $Replacement = $AllCertificates |
        Where-Object {
            $_.Thumbprint -ne $Certificate.Thumbprint -and

            # Same certificate identity
            $_.Subject -eq $Certificate.Subject -and
            $_.Issuer -eq $Certificate.Issuer -and

            # Same intended purposes
            (Get-EkuKey -Certificate $_) -eq $CertificateEku -and

            # Replacement must currently be valid
            $_.NotBefore -le $Now -and
            $_.NotAfter -gt $Now -and

            # Replacement must expire later than the old certificate
            $_.NotAfter -gt $Certificate.NotAfter
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    return $Replacement
}

# ===== Get certificates =====

$AllCertificates = @(
    Get-ChildItem Cert:\LocalMachine\My
)

$CertificatesRequiringAttention = @()
$SupersededCertificates = @()

foreach ($Certificate in $AllCertificates) {
    if ($Certificate.NotAfter -ge $Now.AddDays($WarningDays)) {
        continue
    }

    $Replacement = Find-ReplacementCertificate `
        -Certificate $Certificate `
        -AllCertificates $AllCertificates

    if ($null -ne $Replacement) {
        $SupersededCertificates += [PSCustomObject]@{
            Subject               = $Certificate.Subject
            OldThumbprint         = $Certificate.Thumbprint
            OldExpiry             = $Certificate.NotAfter
            ReplacementThumbprint = $Replacement.Thumbprint
            ReplacementExpiry     = $Replacement.NotAfter
        }
    }
    else {
        $CertificatesRequiringAttention += [PSCustomObject]@{
            Subject       = $Certificate.Subject
            Thumbprint    = $Certificate.Thumbprint
            NotAfter      = $Certificate.NotAfter
            DaysRemaining = ($Certificate.NotAfter - $Now).Days
        }
    }
}

# ===== Output and exit codes =====

if ($CertificatesRequiringAttention.Count -eq 0) {
    Write-Output "OK: No certificates requiring attention within $WarningDays days."

    if ($SupersededCertificates.Count -gt 0) {
        Write-Output ""
        Write-Output "Superseded certificates ignored: $($SupersededCertificates.Count)"

        foreach ($Certificate in $SupersededCertificates) {
            Write-Output "------------------------------------------------------------"
            Write-Output "Subject: $($Certificate.Subject)"
            Write-Output "Old certificate expired/expires: $($Certificate.OldExpiry)"
            Write-Output "Replacement expires: $($Certificate.ReplacementExpiry)"
        }
    }

    exit 0
}
else {
    Write-Output "WARNING: Certificates requiring attention within $WarningDays days:"
    Write-Output "------------------------------------------------------------"

    foreach ($Certificate in $CertificatesRequiringAttention) {
        Write-Output "Subject: $($Certificate.Subject)"
        Write-Output "Expires: $($Certificate.NotAfter)"
        Write-Output "Days Remaining: $($Certificate.DaysRemaining)"
        Write-Output "Thumbprint: $($Certificate.Thumbprint)"
        Write-Output "------------------------------------------------------------"
    }

    if ($SupersededCertificates.Count -gt 0) {
        Write-Output ""
        Write-Output "Superseded certificates ignored: $($SupersededCertificates.Count)"
    }

    exit 1
}