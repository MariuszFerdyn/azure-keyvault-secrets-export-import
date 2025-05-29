# Azure KeyVault Secrets Migration Tool (export/import)

A PowerShell-based solution for exporting and importing secrets from Azure KeyVault, preserving all properties and version history. This tool is especially useful for migrating KeyVault secrets between tenants or environments.

## Features

- **Complete Secret Export**: Exports all secrets including their complete version history
- **Property Preservation**: Preserves all important properties of secrets:
  - Secret name and value
  - Content type
  - Activation date (NotBefore)
  - Expiration date (Expires)
  - Enabled/disabled status
  - All tags
- **Version Management**: Imports secrets in the correct chronological order (oldest first)
- **Detailed Logging**: Provides comprehensive logging of the export and import process
- **Flexible Options**: Includes ability to skip existing secrets or view detailed debug output

## Use Cases

- Migrating KeyVault secrets between Azure subscriptions
- Backing up KeyVault secrets before major changes
- Replicating KeyVault secrets across environments (dev, test, prod)
- Disaster recovery scenarios
- Tenant migration scenarios

## Requirements

- PowerShell 5.1 or higher
- Az PowerShell module (`Install-Module -Name Az`)
- Appropriate permissions on source and target KeyVaults:
  - Source: Secret list, get, and get versions permissions
  - Target: Secret set and update permissions

## Usage

### Exporting Secrets

To export all secrets from a KeyVault:

```powershell
# Connect to Azure first
Connect-AzAccount -SubscriptionId "your-source-subscription-id"

# Export all secrets with all versions
.\KV-Secrets-Export.ps1 -KeyVaultName "source-keyvault-name"

# Export to a specific file
.\KV-Secrets-Export.ps1 -KeyVaultName "source-keyvault-name" -OutputFilePath "C:\path\to\export-file.json"

# Export only current versions (not recommended for migration)
.\KV-Secrets-Export.ps1 -KeyVaultName "source-keyvault-name" -IncludeAllVersions:$false
```

### Importing Secrets

To import secrets to a KeyVault:

```powershell
# Connect to Azure first (might be a different subscription)
Connect-AzAccount -SubscriptionId "your-target-subscription-id"

# Import all secrets
.\KV-Secrets-Import.ps1 -KeyVaultName "target-keyvault-name" -InputFilePath "path\to\exported-secrets.json"

# Skip existing secrets (don't create new versions for secrets that exist)
.\KV-Secrets-Import.ps1 -KeyVaultName "target-keyvault-name" -InputFilePath "path\to\exported-secrets.json" -SkipExisting

# Show detailed output for troubleshooting
.\KV-Secrets-Import.ps1 -KeyVaultName "target-keyvault-name" -InputFilePath "path\to\exported-secrets.json" -DetailedOutput
```

## Security Considerations

- The exported JSON file contains all secret values in plaintext. Ensure this file is properly secured and handled according to your organization's security policies.
- Consider using an encrypted storage solution for the export file.
- Delete the export file securely after migration is complete.
- Use appropriate RBAC permissions in Azure to restrict who can export and import secrets.

## Limitations

- The tool does not migrate KeyVault access policies or network settings
- Does not handle keys or certificates, only secrets
- Maximum JSON export file size is limited by PowerShell's memory constraints
- Date formats in the JSON file may need special handling in some environments

## Tips & Tricks
### Get-AzKeyVaultSecret : Operation returned an invalid status code 'Forbidden'
This error indicates that the secret version is disabled and cannot be exported. The script will continue running without processing this secret version.
