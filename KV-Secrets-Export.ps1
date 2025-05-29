# Script to export all secrets from an Azure KeyVault including all versions,
# with name, value, content type, activation date, expiration date, and tags
#
# Connect to Azure and set current Subscription
# 
# Connect-AzAccount -DeviceCode
# Set-AzContext -Subscription xxx
#
# Example Command
#
# .\KV-Secrets-Export.ps1 -KeyVaultName migrate018873kv -OutputFilePath C:\Users\mf\AppData\Local\Temp\KV\a.json
    
param(
    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFilePath,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAllVersions = $true
)

# Set default value if not provided
if (-not $OutputFilePath) {
    $OutputFilePath = ".\KeyVaultSecrets_$KeyVaultName.json"
}

# Check if user is logged in to Azure
$context = Get-AzContext
if (!$context) {
    Write-Host "You are not logged in to Azure. Please run Connect-AzAccount first." -ForegroundColor Red
    exit
}

# Check if the KeyVault exists
try {
    $keyVault = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction Stop
    Write-Host "Found KeyVault: $KeyVaultName" -ForegroundColor Green
}
catch {
    Write-Host "KeyVault '$KeyVaultName' not found. Please check the name and your permissions." -ForegroundColor Red
    exit
}

# Get all secrets from the KeyVault
try {
    $secretNames = Get-AzKeyVaultSecret -VaultName $KeyVaultName 
    $onlySecrets = $secretNames | Where-Object {
    $_.ContentType -ne "application/x-pkcs12" -and
    $_.ContentType -ne "application/x-pem-file"}
    $secretNames = $onlySecrets | Select-Object -ExpandProperty Name
    Write-Host "Found $($secretNames.Count) secrets in the KeyVault." -ForegroundColor Green
}
catch {
    Write-Host "Failed to retrieve secrets: $_" -ForegroundColor Red
    exit
}

if ($secretNames.Count -eq 0) {
    Write-Host "No secrets found in the KeyVault." -ForegroundColor Yellow
    exit
}

# Create array to store secret details
$exportedSecrets = @()

# Process each secret
foreach ($secretName in $secretNames) {
    Write-Host "Processing secret: $secretName" -ForegroundColor Cyan
    
    try {
        # Get all versions of the secret if requested
        if ($IncludeAllVersions) {
            $secretVersions = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -IncludeVersions
            
            Write-Host "  Found $($secretVersions.Count) versions of secret $secretName" -ForegroundColor Cyan
            
            # Process each version of the secret
            foreach ($secretVersion in $secretVersions) {
                # Get detailed version with ID
                $detailedVersion = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -Version $secretVersion.Version
                
                # Try to get the secret value
                $secretValueText = ""
                try {
                    $secretValue = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -Version $secretVersion.Version -AsPlainText
                    $secretValueText = $secretValue
                }
                catch {
                    Write-Host "  Failed to get plain text value for secret $secretName version $($secretVersion.Version). This could be due to permission issues." -ForegroundColor Yellow
                }
                
                # Create object with secret details
                $secretDetails = [PSCustomObject]@{
                    Name        = $secretName
                    Version     = $detailedVersion.Version
                    Value       = $secretValueText
                    ContentType = $detailedVersion.ContentType
                    Enabled     = $detailedVersion.Enabled
                    Created     = $detailedVersion.Created
                    Updated     = $detailedVersion.Updated
                    Tags        = $detailedVersion.Tags
                    Id          = $detailedVersion.Id
                }
                
                # Add activation date if set
                if ($detailedVersion.Attributes.NotBefore) {
                    $secretDetails | Add-Member -NotePropertyName "ActivationDate" -NotePropertyValue $detailedVersion.Attributes.NotBefore
                }
                
                # Add expiration date if set
                if ($detailedVersion.Attributes.Expires) {
                    $secretDetails | Add-Member -NotePropertyName "ExpirationDate" -NotePropertyValue $detailedVersion.Attributes.Expires
                }
                
                # Add to export array
                $exportedSecrets += $secretDetails
            }
        }
        else {
            # Get only the current version
            $currentVersion = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName
            
            # Try to get the secret value
            $secretValueText = ""
            try {
                $secretValue = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -AsPlainText
                $secretValueText = $secretValue
            }
            catch {
                Write-Host "  Failed to get plain text value for secret $secretName. This could be due to permission issues." -ForegroundColor Yellow
            }
            
            # Create object with secret details
            $secretDetails = [PSCustomObject]@{
                Name        = $secretName
                Version     = $currentVersion.Version
                Value       = $secretValueText
                ContentType = $currentVersion.ContentType
                Enabled     = $currentVersion.Enabled
                Created     = $currentVersion.Created
                Updated     = $currentVersion.Updated
                Tags        = $currentVersion.Tags
                Id          = $currentVersion.Id
            }
            
            # Add activation date if set
            if ($currentVersion.Attributes.NotBefore) {
                $secretDetails | Add-Member -NotePropertyName "ActivationDate" -NotePropertyValue $currentVersion.Attributes.NotBefore
            }
            
            # Add expiration date if set
            if ($currentVersion.Attributes.Expires) {
                $secretDetails | Add-Member -NotePropertyName "ExpirationDate" -NotePropertyValue $currentVersion.Attributes.Expires
            }
            
            # Add to export array
            $exportedSecrets += $secretDetails
        }
    }
    catch {
        Write-Host "  Error processing secret $secretName`: $_" -ForegroundColor Red
    }
}

# Export to JSON file
try {
    $exportedSecrets | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding utf8
    Write-Host "Successfully exported $($exportedSecrets.Count) secret versions to $OutputFilePath" -ForegroundColor Green
}
catch {
    Write-Host "Failed to export secrets to file: $_" -ForegroundColor Red
}
