# Script to import secrets into an Azure KeyVault in chronological order (oldest first),
# including name, value, content type, activation date, expiration date, and tags
#
# Connect to Azure and set current Subscription
# 
# Connect-AzAccount -DeviceCode
# Set-AzContext -Subscriptio  xxx
#
# Example Command
#
# .\KV-Secrets-Import.ps1 -KeyVaultName kvimp01 -InputFilePath C:\Users\mf\AppData\Local\Temp\KV\a.json


param(
    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName,
    
    [Parameter(Mandatory = $true)]
    [string]$InputFilePath,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipExisting = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$DetailedOutput = $false
)

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
    $errorMsg = $_.Exception.Message
    Write-Host "KeyVault '$KeyVaultName' not found. Please check the name and your permissions." -ForegroundColor Red
    Write-Host "Error: $errorMsg" -ForegroundColor Red
    exit
}

# Check if input file exists
if (!(Test-Path -Path $InputFilePath)) {
    Write-Host "Input file '$InputFilePath' not found." -ForegroundColor Red
    exit
}

# Read and parse the JSON file
try {
    $jsonContent = Get-Content -Path $InputFilePath -Raw
    Write-Host "Read JSON file with $((($jsonContent -split "\n").Count)) lines" -ForegroundColor Green
    
    # Show more details if requested
    if ($DetailedOutput) {
        Write-Host "First 200 characters of JSON:" -ForegroundColor DarkGray
        Write-Host $jsonContent.Substring(0, [Math]::Min(200, $jsonContent.Length)) -ForegroundColor DarkGray
    }
    
    $secretsToImport = $jsonContent | ConvertFrom-Json
    Write-Host "Found $($secretsToImport.Count) secret entries in the import file." -ForegroundColor Green
}
catch {
    $errorMsg = $_.Exception.Message
    Write-Host "Failed to parse input file: $errorMsg" -ForegroundColor Red
    exit
}

# Filter out invalid entries (like the ones with null values)
$validSecrets = $secretsToImport | Where-Object { 
    $_.Name -and $_.Value -ne $null -and $_.Version -ne $null
}

if ($validSecrets.Count -lt $secretsToImport.Count) {
    Write-Host "Filtered out $($secretsToImport.Count - $validSecrets.Count) invalid entries." -ForegroundColor Yellow
}

Write-Host "Processing $($validSecrets.Count) valid secret entries." -ForegroundColor Green

# Group secrets by name for processing in chronological order
$secretGroups = $validSecrets | Group-Object -Property Name

Write-Host "Found $($secretGroups.Count) unique secrets to import." -ForegroundColor Green

# Get existing secrets and their versions if we need to skip duplicates
$existingSecretVersions = @{}
if ($SkipExisting) {
    try {
        $existingSecrets = Get-AzKeyVaultSecret -VaultName $KeyVaultName
        foreach ($secret in $existingSecrets) {
            # Get all versions of this secret
            $versions = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secret.Name -IncludeVersions | 
                Select-Object -ExpandProperty Version
            $existingSecretVersions[$secret.Name] = $versions
        }
        Write-Host "Found $($existingSecrets.Count) existing secrets with versions." -ForegroundColor Green
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Host "Warning: Failed to retrieve existing secrets for duplicate checking: $errorMsg" -ForegroundColor Yellow
    }
}

# Import statistics
$importedCount = 0
$skippedCount = 0
$errorCount = 0

# Improved function to parse date from multiple formats
function Parse-FlexibleDate {
    param([string]$dateString)
    
    if ($DetailedOutput) {
        Write-Host "      Parsing date string: '$dateString'" -ForegroundColor DarkGray
    }
    
    if ($null -eq $dateString) {
        if ($DetailedOutput) {
            Write-Host "      Date is null" -ForegroundColor DarkGray
        }
        return $null
    }
    
    # Try parsing /Date(timestamp)/ format
    if ($dateString -match '\/Date\((\d+)\)\/') {
        $timestamp = [long]$matches[1]
        $dateTime = [DateTimeOffset]::FromUnixTimeMilliseconds($timestamp).UtcDateTime
        if ($DetailedOutput) {
            Write-Host "      Successfully parsed timestamp $timestamp to $dateTime" -ForegroundColor DarkGray
        }
        return $dateTime
    }
    
    # Try parsing standard date formats
    try {
        $dateTime = [DateTime]::Parse($dateString)
        if ($DetailedOutput) {
            Write-Host "      Successfully parsed date string to $dateTime" -ForegroundColor DarkGray
        }
        return $dateTime
    }
    catch {
        if ($DetailedOutput) {
            Write-Host "      Failed to parse as DateTime" -ForegroundColor DarkGray
        }
    }
    
    # Try specific formats
    $formats = @(
        'MM/dd/yyyy HH:mm:ss',
        'yyyy-MM-dd HH:mm:ss',
        'yyyy-MM-ddTHH:mm:ss',
        'MM/dd/yyyy'
    )
    
    foreach ($format in $formats) {
        try {
            $dateTime = [DateTime]::ParseExact($dateString, $format, [System.Globalization.CultureInfo]::InvariantCulture)
            if ($DetailedOutput) {
                Write-Host "      Successfully parsed with format $format to $dateTime" -ForegroundColor DarkGray
            }
            return $dateTime
        }
        catch {
            # Continue to next format
        }
    }
    
    Write-Host "      Failed to parse date in any format: $dateString" -ForegroundColor Yellow
    return $null
}

# Display date to string for better output formatting
function Format-DateOutput {
    param([DateTime]$date)
    
    if ($null -eq $date) { return "Not set" }
    return $date.ToString("MM/dd/yyyy HH:mm:ss")
}

# Process each unique secret
foreach ($secretGroup in $secretGroups) {
    $secretName = $secretGroup.Name
    Write-Host "`nProcessing secret: $secretName with $($secretGroup.Group.Count) versions" -ForegroundColor Cyan
    
    # Parse date strings for proper sorting
    foreach ($secret in $secretGroup.Group) {
        if ($secret.Created) {
            $createdDate = Parse-FlexibleDate -dateString $secret.Created
            if ($createdDate) {
                $ticks = $createdDate.Ticks
                $secret | Add-Member -NotePropertyName "CreatedTimestamp" -NotePropertyValue $ticks -Force
            } else {
                # If no valid date found, use a default old date for sorting
                $secret | Add-Member -NotePropertyName "CreatedTimestamp" -NotePropertyValue 0 -Force
            }
        } else {
            # If no valid date found, use a default old date for sorting
            $secret | Add-Member -NotePropertyName "CreatedTimestamp" -NotePropertyValue 0 -Force
        }
    }
    
    # Sort versions by creation timestamp (ascending - oldest first)
    $sortedVersions = $secretGroup.Group | Sort-Object -Property CreatedTimestamp
    
    # Process each version in chronological order
    foreach ($secret in $sortedVersions) {
        $versionInfo = if ($secret.Version) { " (Version: $($secret.Version))" } else { "" }
        $createdDate = if ($secret.Created) { 
            $dateObj = Parse-FlexibleDate -dateString $secret.Created
            if ($dateObj) {
                " created on " + (Format-DateOutput -date $dateObj)
            } else {
                " with creation date $($secret.Created)"
            }
        } else { "" }
        
        Write-Host "  Importing version of $secretName$versionInfo$createdDate" -ForegroundColor Cyan
        
        # Check if this specific version should be skipped
        if ($SkipExisting -and 
            $existingSecretVersions.ContainsKey($secretName) -and 
            $existingSecretVersions[$secretName] -contains $secret.Version) {
            Write-Host "    Version already exists. Skipping." -ForegroundColor Yellow
            $skippedCount++
            continue
        }
        
        # Show more details if requested
        if ($DetailedOutput) {
            Write-Host "    Secret object properties:" -ForegroundColor DarkGray
            $secret.PSObject.Properties | ForEach-Object {
                Write-Host "      $($_.Name): $($_.Value)" -ForegroundColor DarkGray
            }
        }
        
        try {
            # Handle the secret value
            $secretValue = $secret.Value
            if ($secretValue -is [System.Collections.IDictionary] -or $secretValue -is [PSCustomObject]) {
                $secretValue = ($secretValue | ConvertTo-Json -Compress)
            }
            
            # Convert to secure string
            $secureValue = ConvertTo-SecureString -String $secretValue -AsPlainText -Force
            
            # Create secret parameters
            $secretParams = @{
                VaultName   = $KeyVaultName
                Name        = $secretName
                SecretValue = $secureValue
            }
            
            if ($secret.ContentType) {
                $secretParams.Add("ContentType", $secret.ContentType)
            }
            
            # Check for and parse activation date
            if ($secret.PSObject.Properties.Name -contains "ActivationDate" -and $secret.ActivationDate) {
                Write-Host "    Found ActivationDate: $($secret.ActivationDate)" -ForegroundColor DarkCyan
                $activationDate = Parse-FlexibleDate -dateString $secret.ActivationDate
                if ($activationDate) {
                    $secretParams.Add("NotBefore", $activationDate)
                    Write-Host "    Adding NotBefore: $(Format-DateOutput -date $activationDate)" -ForegroundColor Green
                } else {
                    Write-Host "    Failed to parse ActivationDate, not setting NotBefore" -ForegroundColor Yellow
                }
            }
            
            # Check for and parse expiration date
            if ($secret.PSObject.Properties.Name -contains "ExpirationDate" -and $secret.ExpirationDate) {
                Write-Host "    Found ExpirationDate: $($secret.ExpirationDate)" -ForegroundColor DarkCyan
                $expirationDate = Parse-FlexibleDate -dateString $secret.ExpirationDate
                if ($expirationDate) {
                    $secretParams.Add("Expires", $expirationDate)
                    Write-Host "    Adding Expires: $(Format-DateOutput -date $expirationDate)" -ForegroundColor Green
                } else {
                    Write-Host "    Failed to parse ExpirationDate, not setting Expires" -ForegroundColor Yellow
                }
            }
            
            # Add tags if they exist
            if ($secret.Tags -and $secret.Tags.PSObject.Properties.Count -gt 0) {
                $tags = @{}
                $secret.Tags.PSObject.Properties | ForEach-Object { $tags[$_.Name] = $_.Value }
                $secretParams.Add("Tag", $tags)
            }
            
            # Show more details about parameters if requested
            if ($DetailedOutput) {
                Write-Host "    Parameters for Set-AzKeyVaultSecret:" -ForegroundColor DarkGray
                $secretParams.Keys | ForEach-Object {
                    $paramValue = if ($_ -eq "SecretValue") { 
                        "SecureString" 
                    } elseif ($_ -eq "NotBefore" -or $_ -eq "Expires") { 
                        Format-DateOutput -date $secretParams[$_] 
                    } elseif ($_ -eq "Tag" -and $secretParams[$_] -is [Hashtable]) {
                        "Hashtable with $($secretParams[$_].Count) entries"
                    } else { 
                        $secretParams[$_] 
                    }
                    Write-Host "      $_ = $paramValue" -ForegroundColor DarkGray
                }
            }
            
            # Create the secret (this will create a new version)
            $newSecret = Set-AzKeyVaultSecret @secretParams
            Write-Host "    Created secret with ID: $($newSecret.Id)" -ForegroundColor Green
            
            # Handle enabled/disabled state separately as it needs to be updated after creation
            if ($secret.PSObject.Properties.Name -contains "Enabled" -and $null -ne $secret.Enabled -and $secret.Enabled -eq $false) {
                $updateParams = @{
                    VaultName = $KeyVaultName
                    Name      = $secretName
                    Version   = $newSecret.Version
                    Disable   = $true
                }
                
                $updatedSecret = Update-AzKeyVaultSecret @updateParams
                Write-Host "    Disabled secret." -ForegroundColor DarkCyan
            }
            
            # Verify the created secret
            $verifySecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secretName -Version $newSecret.Version
            
            Write-Host "    Verified secret dates:" -ForegroundColor Green
            if ($verifySecret.Attributes.NotBefore) {
                Write-Host "      NotBefore: $(Format-DateOutput -date $verifySecret.Attributes.NotBefore)" -ForegroundColor Green
            } else {
                Write-Host "      NotBefore: Not set" -ForegroundColor Yellow
            }
            
            if ($verifySecret.Attributes.Expires) {
                Write-Host "      Expires: $(Format-DateOutput -date $verifySecret.Attributes.Expires)" -ForegroundColor Green
            } else {
                Write-Host "      Expires: Not set" -ForegroundColor Yellow
            }
            
            $importedCount++
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Host "    Failed to import version of secret $secretName`: $errorMsg" -ForegroundColor Red
            if ($DetailedOutput) {
                Write-Host "    Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor DarkRed
            }
            $errorCount++
        }
    }
}

# Summary
Write-Host "`nImport Summary:" -ForegroundColor Cyan
Write-Host "  Successfully imported: $importedCount secret versions" -ForegroundColor Green
if ($skippedCount -gt 0) {
    Write-Host "  Skipped (already existed): $skippedCount secret versions" -ForegroundColor Yellow
}
if ($errorCount -gt 0) {
    Write-Host "  Failed to import: $errorCount secret versions" -ForegroundColor Red
}
