Import-Module ./JWT/JWT.psm1
# Install-Module JWT

$pfxFile = 'keystore-ms.pfx'
# $Cert = Get-PfxCertificate $pfxFile
# If you can include the PFX password in the code, you might use the below
$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxFile, "password")

$oauthProviderUrlBase = 'https://stig-manager-auth.azurewebsites.net/auth/realms/stigman'
$stigmanApiUrlBase = 'https://stig-manager.azurewebsites.net/api'

$oauthClientId = 'stigman-watcher'
$oauthScopes = "stig-manager:stig:read stig-manager:collection stig-manager:user:read"

function Read-SMOpenIdConfiguration {
  $url = "$oauthProviderUrlBase/.well-known/openid-configuration"
  Invoke-RestMethod -Method GET -Uri $url
}

function Read-SMOAuthToken {
  param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('device_code','client_credentials_secret', 'client_credentials_jwt')]
    [string]$GrantType,
    $DeviceCode,
    $ClientId,
    $ClientSecret,
    $Uri,
    $Cert,
    $Scopes
  )
  Switch ($GrantType) {
    'device_code' {
      $body = @{
        grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
        client_id = $ClientId
        device_code = $DeviceCode
      }
      break
    }
    'client_credentials_secret' {
      $body = @{
        grant_type = 'client_credentials'
        client_id = $ClientId
        client_secret = $ClientSecret
      }
      break
    }
    'client_credentials_jwt' {
      $json = ConvertTo-Json @{
        iss = $ClientId
        sub = $ClientId
        aud = $Uri
        jti = (1..16|ForEach-Object{[byte](Get-Random -Max 256)}|ForEach-Object ToString X2) -join ''
        exp = ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds() + 300
      }
      $signed = New-Jwt -Cert $Cert -PayloadJson $json
      $body = @{
        grant_type = 'client_credentials'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion = $signed
        scope = $Scopes
      }
      break
    }
  }
  $contentType = 'application/x-www-form-urlencoded' 
  Invoke-RestMethod -Method POST -Uri $Uri -body $body -ContentType $contentType
}

function Read-SMApiCollections {
  param (
    $AccessToken
  )
  $headers = @{
    Authorization="Bearer $AccessToken"
  }
  $url = "$stigmanApiUrlBase/collections"
  Invoke-RestMethod -Method GET -Uri $url -Headers $headers
}

function Read-SMApiUserInfo {
  param (
    $AccessToken
  )
  $headers = @{
    Authorization="Bearer $AccessToken"
  }
  $url = "$stigmanApiUrlBase/user"
  Invoke-RestMethod -Method GET -Uri $url -Headers $headers
}

try {
  $openIdConfiguration = Read-SMOpenIdConfiguration
}
catch {
  Write-Host "Error getting OpenID Configuration from $oauthProviderUrlBase"
  Write-Host $_
  exit
}

try {
  $tokenResponse = Read-SMOAuthToken `
    -Uri $openIdConfiguration.token_endpoint `
    -GrantType "client_credentials_jwt" `
    -ClientId $oauthClientId `
    -Cert $Cert `
    -Scopes $oauthScopes
}
catch {
  $_
}
Write-Host "Authentication has completed."

$tokenResponse

Write-Host "Requesting user information from STIG Manager."
Read-SMApiUserInfo -AccessToken $tokenResponse.access_token

Write-Host "Requesting collection information from STIG Manager."
Read-SMApiCollections -AccessToken $tokenResponse.access_token
