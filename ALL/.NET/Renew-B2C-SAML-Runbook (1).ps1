<#
.SYNOPSIS
    Production Azure Automation runbook for Azure AD B2C / IEF SAML signing
    certificate renewal.

.DESCRIPTION
    JITA / production-scoped version.

    This runbook:
      - Authenticates to Microsoft Graph with an App Registration and client secret.
      - Reads configuration from Azure Automation assets.
      - Requires an explicit B2C-KeyNames allow-list; it never scans/renews every key.
      - Uses Graph getActiveKey to inspect the key B2C currently considers active.
      - Operates only on existing RSA X.509 SAML signing certificate keysets.
      - Skips keys with no expiration date.
      - Renews at B2C-ExpiryThresholdDays (default 30) before expiry.
      - Forces November/December/January expiries to renew starting in October.
      - Uploads the new PFX to the SAME existing keyset; it does not delete/recreate
        the keyset and does not change the StorageReferenceId / policy-key name.
      - Fails closed if the target is empty, non-RSA, non-certificate, encryption-use,
        missing expiry, or certificate generation is unavailable.

    Microsoft Graph API used:
      https://graph.microsoft.com/beta/trustFramework/keySets

    Required Microsoft Graph APPLICATION permission (admin consent required):
      TrustFrameworkKeySet.ReadWrite.All

    Required Azure Automation assets:
      Variable   B2C-TenantId                Example: <B2C tenant GUID or tenant domain>
      Variable   B2C-ClientId                Example: <App Registration client ID>
      Credential B2C-Credential              Preferred. Password = client secret VALUE
                   OR
      Variable   B2C-ClientSecret            Encrypted = Yes; value = client secret VALUE
      Variable   B2C-KeyNames                REQUIRED allow-list, comma-separated
                                             Example: B2C_1A_PalantirSAMLSigning

    Optional Azure Automation assets:
      Variable   B2C-ExpiryThresholdDays     Default: 30
      Variable   B2C-CertValidityDays        Default: 365
      Variable   B2C-BlackoutExpiryMonths    Default: 11,12,1
      Variable   B2C-BlackoutRenewByMonth    Default: 10

    Recommended first production validation:
      1. Run with -ListOnly.
      2. Run with -WhatIf.
      3. Only then run normally.

.NOTES
    This runbook intentionally does NOT:
      - prompt interactively for a secret,
      - read local files/environment secrets,
      - renew all B2C keys,
      - renew symmetric/manual secrets,
      - generate a bare JWK fallback,
      - delete or recreate the target SAML keyset.

    The trustFramework keySet endpoints used here are Microsoft Graph beta APIs.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ListOnly
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$graphBaseUrl = 'https://graph.microsoft.com/beta'
$requiredGraphRole = 'TrustFrameworkKeySet.ReadWrite.All'

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet('INFO','WARN','ERROR','ACTION','SUCCESS','DEBUG')][string]$Level = 'INFO'
    )

    $timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "[$timestamp UTC] [$Level] $Message"
}

function Get-AutomationVariableSafe {
    param([Parameter(Mandatory = $true)][string]$Name)

    if (-not (Get-Command -Name Get-AutomationVariable -ErrorAction SilentlyContinue)) {
        throw "Get-AutomationVariable is unavailable. This production script is intended to run in Azure Automation."
    }

    try {
        $value = Get-AutomationVariable -Name $Name -ErrorAction Stop
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            return $value
        }
    }
    catch {
        return $null
    }

    return $null
}

function Get-RequiredAutomationVariable {
    param([Parameter(Mandatory = $true)][string]$Name)

    $value = Get-AutomationVariableSafe -Name $Name
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
        throw "Required Azure Automation variable '$Name' is missing or empty."
    }

    return $value
}

function Get-IntAutomationVariable {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$DefaultValue,
        [Parameter(Mandatory = $true)][int]$Minimum,
        [Parameter(Mandatory = $true)][int]$Maximum
    )

    $raw = Get-AutomationVariableSafe -Name $Name
    if ($null -eq $raw) {
        return $DefaultValue
    }

    $parsed = 0
    if (-not [int]::TryParse(([string]$raw).Trim(), [ref]$parsed)) {
        throw "Automation variable '$Name' must be an integer. Current value: '$raw'."
    }

    if ($parsed -lt $Minimum -or $parsed -gt $Maximum) {
        throw "Automation variable '$Name' must be between $Minimum and $Maximum. Current value: $parsed."
    }

    return $parsed
}


function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-PlainText {
    param([Parameter(Mandatory = $true)][SecureString]$Secure)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Trim()
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-RunbookClientSecret {
    if (Get-Command -Name Get-AutomationPSCredential -ErrorAction SilentlyContinue) {
        $credential = Get-AutomationPSCredential -Name 'B2C-Credential' -ErrorAction SilentlyContinue
        if ($null -ne $credential -and $null -ne $credential.Password) {
            Write-Log "Using Azure Automation Credential asset 'B2C-Credential'."
            return $credential.Password
        }
    }

    $encryptedVariable = Get-AutomationVariableSafe -Name 'B2C-ClientSecret'
    if ($null -ne $encryptedVariable -and -not [string]::IsNullOrWhiteSpace([string]$encryptedVariable)) {
        Write-Log "Using encrypted Azure Automation variable 'B2C-ClientSecret'."
        return ConvertTo-SecureString -String ([string]$encryptedVariable).Trim() -AsPlainText -Force
    }

    throw "No app-registration secret is configured. Create Credential asset 'B2C-Credential' (preferred) or encrypted variable 'B2C-ClientSecret'."
}

function ConvertFrom-JwtPayload {
    param([Parameter(Mandatory = $true)][string]$Token)

    $parts = $Token.Split('.')
    if ($parts.Count -ne 3) {
        throw 'The token endpoint returned a value that is not a valid JWT.'
    }

    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
        0 { }
        default { throw 'JWT payload has invalid Base64Url length.' }
    }

    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    return $json | ConvertFrom-Json
}

function Get-AccessToken {
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][SecureString]$ClientSecret
    )

    Write-Log 'Acquiring Microsoft Graph access token using app registration client credentials...'

    $plainSecret = ConvertTo-PlainText -Secure $ClientSecret
    try {
        $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $body = @{
            client_id     = $ClientId
            client_secret = $plainSecret
            scope         = 'https://graph.microsoft.com/.default'
            grant_type    = 'client_credentials'
        }

        $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'
        if (-not $response.access_token) {
            throw 'Microsoft identity platform did not return an access_token.'
        }

        return ([string]$response.access_token).Trim()
    }
    finally {
        $plainSecret = $null
    }
}

function Assert-RequiredGraphRole {
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$RequiredRole
    )

    $claims = ConvertFrom-JwtPayload -Token $Token
    $roles = @(Get-ObjectPropertyValue -InputObject $claims -Name 'roles')
    if ($roles -notcontains $RequiredRole) {
        $present = if ($roles.Count -gt 0) { $roles -join ', ' } else { '<none>' }
        throw "The app-registration access token does not contain required Microsoft Graph application permission '$RequiredRole'. Token roles: $present. Grant admin consent before running this in production."
    }

    Write-Log "Verified Graph application permission: $RequiredRole." 'SUCCESS'
}

function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $false)]$Body
    )

    $headers = @{
        Authorization = "Bearer $Token"
        Accept        = 'application/json'
    }

    $maxAttempts = 5
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            if ($null -ne $Body) {
                $headers['Content-Type'] = 'application/json'
                $jsonBody = $Body | ConvertTo-Json -Depth 10 -Compress
                return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $headers -Body $jsonBody -ContentType 'application/json'
            }

            return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $headers
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { }
            }

            if (($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -lt 600)) -and $attempt -lt $maxAttempts) {
                $retrySeconds = 5 * $attempt
                try {
                    $retryHeader = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                    if ($retryHeader -and $retryHeader -gt 0) {
                        $retrySeconds = [math]::Ceiling($retryHeader)
                    }
                }
                catch { }

                Write-Log "Graph request returned HTTP $statusCode. Retrying in $retrySeconds seconds (attempt $attempt/$maxAttempts)." 'WARN'
                Start-Sleep -Seconds $retrySeconds
                continue
            }

            $details = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            throw "Microsoft Graph request failed: $Method $Uri; HTTP=$statusCode; $details"
        }
    }
}

function Get-PolicyKeySet {
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$KeySetId
    )

    return Invoke-GraphRequest -Method GET -Uri "$graphBaseUrl/trustFramework/keySets/$KeySetId" -Token $Token
}

function Get-PolicyKeySetActiveKey {
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$KeySetId
    )

    return Invoke-GraphRequest -Method GET -Uri "$graphBaseUrl/trustFramework/keySets/$KeySetId/getActiveKey" -Token $Token
}

function New-SamlSigningCertificatePfx {
    param(
        [Parameter(Mandatory = $true)][string]$SubjectName,
        [Parameter(Mandatory = $true)][int]$ValidityDays
    )

    if (-not (Get-Command -Name New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
        throw "New-SelfSignedCertificate is unavailable in this Azure Automation runtime. The runbook is intentionally refusing a bare-JWK fallback. Use a compatible Windows runtime/worker with the PKI cmdlet available."
    }

    # Preserve the rollover behavior from the validated source script: the new key is
    # future-dated by four hours while the existing certificate remains in the same keyset.
    $notBefore = (Get-Date).AddHours(4)
    $notAfter = $notBefore.AddDays($ValidityDays)

    $certificate = New-SelfSignedCertificate `
        -Subject "CN=$SubjectName" `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -NotBefore $notBefore `
        -NotAfter $notAfter `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature `
        -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' `
        -KeySpec Signature

    try {
        $pfxPassword = [Guid]::NewGuid().ToString('N')
        $pfxBytes = $certificate.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
            $pfxPassword
        )

        return [PSCustomObject]@{
            PfxBase64 = [Convert]::ToBase64String($pfxBytes)
            Password  = $pfxPassword
            Thumbprint = $certificate.Thumbprint
            NotBefore = $certificate.NotBefore.ToUniversalTime()
            NotAfter  = $certificate.NotAfter.ToUniversalTime()
        }
    }
    finally {
        Remove-Item -Path "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
}

function Add-Pkcs12ToPolicyKeySet {
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$KeySetId,
        [Parameter(Mandatory = $true)][string]$PfxBase64,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $body = @{
        key      = $PfxBase64
        password = $Password
    }

    return Invoke-GraphRequest -Method POST -Uri "$graphBaseUrl/trustFramework/keySets/$KeySetId/uploadPkcs12" -Token $Token -Body $body
}

function Test-BlackoutRenewalNeeded {
    param(
        [Parameter(Mandatory = $true)][datetime]$ExpiryUtc,
        [Parameter(Mandatory = $true)][int[]]$BlackoutMonths,
        [Parameter(Mandatory = $true)][int]$RenewByMonth
    )

    if ($BlackoutMonths -notcontains $ExpiryUtc.Month) {
        return $false
    }

    # A January expiry belongs to the October run-up in the previous calendar year.
    $renewByYear = if ($ExpiryUtc.Month -lt $RenewByMonth) { $ExpiryUtc.Year - 1 } else { $ExpiryUtc.Year }
    $renewByUtc = [DateTime]::SpecifyKind(
        [DateTime]::new($renewByYear, $RenewByMonth, 1, 0, 0, 0),
        [DateTimeKind]::Utc
    )

    return ([DateTime]::UtcNow -ge $renewByUtc)
}

# -----------------------------------------------------------------------------
# Load and validate Azure Automation configuration
# -----------------------------------------------------------------------------
$tenantId = ([string](Get-RequiredAutomationVariable -Name 'B2C-TenantId')).Trim()
$clientId = ([string](Get-RequiredAutomationVariable -Name 'B2C-ClientId')).Trim()
$clientSecret = Get-RunbookClientSecret

$expiryThresholdDays = Get-IntAutomationVariable -Name 'B2C-ExpiryThresholdDays' -DefaultValue 30 -Minimum 1 -Maximum 180
$certValidityDays = Get-IntAutomationVariable -Name 'B2C-CertValidityDays' -DefaultValue 365 -Minimum 30 -Maximum 1095
$blackoutRenewByMonth = Get-IntAutomationVariable -Name 'B2C-BlackoutRenewByMonth' -DefaultValue 10 -Minimum 1 -Maximum 12

$blackoutRaw = Get-AutomationVariableSafe -Name 'B2C-BlackoutExpiryMonths'
if ($null -eq $blackoutRaw) {
    $blackoutExpiryMonths = @(11, 12, 1)
}
else {
    $blackoutExpiryMonths = @(
        ([string]$blackoutRaw -split ',') |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne '' } |
            ForEach-Object { [int]$_ }
    )
}

if ($blackoutExpiryMonths.Count -eq 0 -or ($blackoutExpiryMonths | Where-Object { $_ -lt 1 -or $_ -gt 12 })) {
    throw "B2C-BlackoutExpiryMonths must contain valid month numbers 1-12, for example '11,12,1'."
}

$keyNamesRaw = Get-RequiredAutomationVariable -Name 'B2C-KeyNames'
$keyNames = @(
    ([string]$keyNamesRaw -split ',') |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' } |
        Select-Object -Unique
)

if ($keyNames.Count -eq 0) {
    throw "B2C-KeyNames must contain at least one explicit SAML signing key. The production runbook will not scan all B2C keys."
}

$protectedKeySetNames = @(
    'B2C_1A_TokenSigningKeyContainer',
    'B2C_1A_TokenEncryptionKeyContainer',
    'B2C_1A_AdminClientEncryptionKeyContainer'
)

foreach ($keyName in $keyNames) {
    if ($protectedKeySetNames -contains $keyName) {
        throw "B2C-KeyNames contains protected system key '$keyName'. Remove it before running."
    }

    if ($keyName -notmatch '^B2C_1A_') {
        throw "B2C-KeyNames contains '$keyName', which is not a B2C_1A_* policy-key ID."
    }

    if ($keyName -notmatch '(?i)SAML') {
        throw "B2C-KeyNames contains '$keyName', which does not contain 'SAML'. This JITA runbook is intentionally scoped to SAML keys only."
    }
}

Write-Log "Configuration loaded. Target key(s): $($keyNames -join ', ')."
Write-Log "Renewal threshold=$expiryThresholdDays days; new certificate validity=$certValidityDays days; blackout months=$($blackoutExpiryMonths -join ','); renew-by month=$blackoutRenewByMonth."

# Unattended Azure Automation jobs must not pause for confirmation prompts.
$ConfirmPreference = 'None'

# -----------------------------------------------------------------------------
# Authenticate and verify permission
# -----------------------------------------------------------------------------
$token = Get-AccessToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
Assert-RequiredGraphRole -Token $token -RequiredRole $requiredGraphRole

# -----------------------------------------------------------------------------
# Evaluate only explicitly allow-listed SAML signing certificate keysets
# -----------------------------------------------------------------------------
$summary = @()

foreach ($keySetId in $keyNames) {
    $oldExpiry = $null
    try {
        Write-Log "$keySetId - validating target policy key."

        # Confirm the keyset exists and retain its keys so duplicate pending rollovers can be detected.
        $keySetDetail = Get-PolicyKeySet -Token $token -KeySetId $keySetId
        $activeKey = Get-PolicyKeySetActiveKey -Token $token -KeySetId $keySetId

        if ($null -eq $activeKey) {
            throw 'No active key was returned. Production runbook will not create a certificate in an empty/unknown keyset.'
        }

        $activeKty = Get-ObjectPropertyValue -InputObject $activeKey -Name 'kty'
        $activeX5c = Get-ObjectPropertyValue -InputObject $activeKey -Name 'x5c'
        $activeUse = Get-ObjectPropertyValue -InputObject $activeKey -Name 'use'
        $activeExp = Get-ObjectPropertyValue -InputObject $activeKey -Name 'exp'

        if ($activeKty -ne 'RSA') {
            throw "Active key is not RSA (kty=$activeKty). Only RSA X.509 SAML signing certificates are allowed."
        }

        if (-not $activeX5c -or @($activeX5c).Count -eq 0) {
            throw 'Active key is not X.509 certificate-based (x5c is missing). Raw-JWK migration is intentionally disabled in this production runbook.'
        }

        $keyUse = if ($activeUse) { ([string]$activeUse).ToLowerInvariant() } else { 'sig' }
        if ($keyUse -ne 'sig') {
            throw "Active key use is '$keyUse'. This JITA runbook is restricted to SAML signing certificates (use=sig)."
        }

        if ($null -eq $activeExp -or [long]$activeExp -le 0) {
            Write-Log "$keySetId - no certificate expiry is set; skipping by design." 'WARN'
            $summary += [PSCustomObject]@{
                Name      = $keySetId
                OldExpiry = $null
                Status    = 'Skipped (no expiry set)'
                NewExpiry = $null
            }
            continue
        }

        $oldExpiry = [DateTimeOffset]::FromUnixTimeSeconds([long]$activeExp).UtcDateTime
        $daysToExpiry = ($oldExpiry - [DateTime]::UtcNow).TotalDays
        $roundedDays = [math]::Round($daysToExpiry, 1)

        # If a previous run already uploaded a successor whose nbf is still in the future,
        # do not upload another certificate while getActiveKey still reports the old key.
        $allKeys = @(Get-ObjectPropertyValue -InputObject $keySetDetail -Name 'keys')
        $nowUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $pendingSuccessor = @(
            $allKeys | Where-Object {
                $candidateKty = Get-ObjectPropertyValue -InputObject $_ -Name 'kty'
                $candidateX5c = Get-ObjectPropertyValue -InputObject $_ -Name 'x5c'
                $candidateNbf = Get-ObjectPropertyValue -InputObject $_ -Name 'nbf'
                $candidateExp = Get-ObjectPropertyValue -InputObject $_ -Name 'exp'

                $candidateKty -eq 'RSA' -and
                $candidateX5c -and
                $null -ne $candidateNbf -and [long]$candidateNbf -gt $nowUnix -and
                $null -ne $candidateExp -and [long]$candidateExp -gt [long]$activeExp
            } | Sort-Object { [long](Get-ObjectPropertyValue -InputObject $_ -Name 'nbf') } -Descending
        ) | Select-Object -First 1

        if ($pendingSuccessor) {
            $pendingNbf = [DateTimeOffset]::FromUnixTimeSeconds([long](Get-ObjectPropertyValue -InputObject $pendingSuccessor -Name 'nbf')).UtcDateTime
            $pendingExp = [DateTimeOffset]::FromUnixTimeSeconds([long](Get-ObjectPropertyValue -InputObject $pendingSuccessor -Name 'exp')).UtcDateTime
            Write-Log "$keySetId - successor certificate is already pending (nbf=$($pendingNbf.ToString('u')), exp=$($pendingExp.ToString('u'))). No duplicate upload." 'WARN'
            $summary += [PSCustomObject]@{
                Name      = $keySetId
                OldExpiry = $oldExpiry
                Status    = 'Pending rollover already scheduled'
                NewExpiry = $pendingExp
            }
            continue
        }

        $blackoutNeeded = Test-BlackoutRenewalNeeded `
            -ExpiryUtc $oldExpiry `
            -BlackoutMonths $blackoutExpiryMonths `
            -RenewByMonth $blackoutRenewByMonth

        $needsRenewal = ($daysToExpiry -le $expiryThresholdDays) -or $blackoutNeeded

        Write-Log "$keySetId - active X.509 signing certificate expires $($oldExpiry.ToString('u')) ($roundedDays days remaining)."

        if ($ListOnly) {
            $status = if (-not $needsRenewal) {
                "OK ($roundedDays days left)"
            }
            elseif ($blackoutNeeded -and $daysToExpiry -gt $expiryThresholdDays) {
                "Needs early renewal (blackout-window expiry; $roundedDays days left)"
            }
            else {
                "Needs renewal ($roundedDays days left)"
            }

            $summary += [PSCustomObject]@{
                Name      = $keySetId
                OldExpiry = $oldExpiry
                Status    = $status
                NewExpiry = $null
            }
            continue
        }

        if (-not $needsRenewal) {
            Write-Log "$keySetId - not due for renewal. No change."
            $summary += [PSCustomObject]@{
                Name      = $keySetId
                OldExpiry = $oldExpiry
                Status    = 'OK (not near expiry)'
                NewExpiry = $null
            }
            continue
        }

        if ($blackoutNeeded -and $daysToExpiry -gt $expiryThresholdDays) {
            Write-Log "$keySetId - expiry falls in configured blackout months; forcing October/renew-by-month rollover." 'WARN'
        }

        $subjectName = $keySetId -replace '^B2C_1A_', ''

        if ($PSCmdlet.ShouldProcess($keySetId, "Upload new X.509 SAML signing certificate to same B2C policy keyset")) {
            Write-Log "$keySetId - generating new RSA 2048/SHA256 signing certificate (validity=$certValidityDays days)." 'ACTION'
            $pfx = New-SamlSigningCertificatePfx -SubjectName $subjectName -ValidityDays $certValidityDays

            Write-Log "$keySetId - uploading PFX to the SAME existing policy keyset. Keyset name is not deleted or recreated." 'ACTION'
            $newKey = Add-Pkcs12ToPolicyKeySet `
                -Token $token `
                -KeySetId $keySetId `
                -PfxBase64 $pfx.PfxBase64 `
                -Password $pfx.Password

            if ($null -eq $newKey) {
                throw 'Graph uploadPkcs12 returned no key object.'
            }

            $newX5c = Get-ObjectPropertyValue -InputObject $newKey -Name 'x5c'
            $newExp = Get-ObjectPropertyValue -InputObject $newKey -Name 'exp'

            if (-not $newX5c -or @($newX5c).Count -eq 0) {
                throw 'Graph upload completed but returned key does not contain x5c. Treating renewal as failed.'
            }

            if ($null -eq $newExp -or [long]$newExp -le 0) {
                throw 'Graph upload completed but returned key has no valid expiry. Treating renewal as failed.'
            }

            $newExpiry = [DateTimeOffset]::FromUnixTimeSeconds([long]$newExp).UtcDateTime
            if ($newExpiry -le $oldExpiry) {
                throw "New certificate expiry ($newExpiry UTC) is not later than old expiry ($oldExpiry UTC)."
            }

            Write-Log "$keySetId - renewal upload succeeded. Old expiry=$($oldExpiry.ToString('u')); new expiry=$($newExpiry.ToString('u')); new thumbprint=$($pfx.Thumbprint)." 'SUCCESS'
            $summary += [PSCustomObject]@{
                Name      = $keySetId
                OldExpiry = $oldExpiry
                Status    = 'Renewed'
                NewExpiry = $newExpiry
            }
        }
        else {
            $summary += [PSCustomObject]@{
                Name      = $keySetId
                OldExpiry = $oldExpiry
                Status    = 'Would renew (WhatIf)'
                NewExpiry = $null
            }
        }
    }
    catch {
        Write-Log "$keySetId - FAILED: $($_.Exception.Message)" 'ERROR'
        $summary += [PSCustomObject]@{
            Name      = $keySetId
            OldExpiry = $oldExpiry
            Status    = "Error: $($_.Exception.Message)"
            NewExpiry = $null
        }
    }
}

Write-Log '----- Production SAML Renewal Summary -----'
$summary | Format-Table -AutoSize | Out-String | Write-Output

$failures = @($summary | Where-Object { $_.Status -like 'Error:*' })
if ($failures.Count -gt 0) {
    throw "$($failures.Count) target SAML policy key(s) failed. Review the Azure Automation job output."
}
