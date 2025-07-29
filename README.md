# HelloID-Conn-Prov-Target-NokiLock-Students

<!--
** for extra information about alert syntax please refer to [Alerts](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#alerts)
-->

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-NokiLock-Students](#helloid-conn-prov-target-nokilock-students)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported  features](#supported--features)
  - [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Account Reference](#account-reference)
    - [Scope](#scope)
  - [Remarks](#remarks)
    - [`getUsers`](#getusers)
    - [Reboarding](#reboarding)
    - [Number](#number)
    - [CardID](#cardid)
    - [UserID or: `id`](#userid-or-id)
    - [Role](#role)
    - [CustomerID / CustomerName](#customerid--customername)
    - [Concurrent sessions](#concurrent-sessions)
  - [Development resources](#development-resources)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-NokiLock-Students_ is a _target_ connector. _HelloID-Conn-Prov-Target-NokiLock-Students_ provides a set of REST API's that allow you to programmatically interact with its data.

## Supported  features

The following features are available:

| Feature                                   | Supported | Actions                                 | Remarks |
| ----------------------------------------- | --------- | --------------------------------------- | ------- |
| **Account Lifecycle**                     | ✅         | Create, Update, Enable, Disable, Delete |         |
| **Permissions**                           | ✅         | _                                       |         |
| **Resources**                             | ❌         | -                                       |         |
| **Entitlement Import: Accounts**          | ✅         | -                                       |         |
| **Entitlement Import: Permissions**       | ❌         | -                                       |         |
| **Governance Reconciliation Resolutions** | ✅         | -                                       |         |

## Getting started

### Prerequisites

<!--
Describe the specific requirements that must be met before using this connector, such as the need for an agent, a certificate or IP whitelisting.

**Please ensure to list the requirements using bullet points for clarity.**

Example:

- **SSL Certificate**:<br>
  A valid SSL certificate must be installed on the server to ensure secure communication. The certificate should be trusted by a recognized Certificate Authority (CA) and must not be self-signed.
- **IP Whitelisting**:<br>
  The IP addresses used by the connector must be whitelisted on the target system's firewall to allow access. Ensure that the firewall rules are configured to permit incoming and outgoing connections from these IPs.
-->

### Connection settings

The following settings are required to connect to the API.

| Setting      | Description                        | Mandatory |
| ------------ | ---------------------------------- | --------- |
| UserName     | The UserName to connect to the API | Yes       |
| Password     | The Password to connect to the API | Yes       |
| BaseUrl      | The URL to the API                 | Yes       |
| CustomerID   | The CustomerID                     | Yes       |
| CustomerName | The CustomerName                   | Yes       |

### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _{connectorName}_ to a person in _HelloID_.

| Setting                   | Value        |
| ------------------------- | ------------ |
| Enable correlation        | `True`       |
| Person correlation field  | `ExternalId` |
| Account correlation field | `cardID`     |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

### Account Reference

The account reference is populated with the property `cardID` property.

### Scope

The _NokiLock_ connector exclusively manages user accounts. Cards and authorizations are not supported.

## Remarks

### `getUsers`

To validate whether an account exists within _NokiLock_, the `getUsers` SOAP action is used. This action optionally accepts a filter to narrow the results based on a specific _`cardID`_.

> [!NOTE]
> The filter exclusively supports the _`cardID`_ attribute. The value of the _`cardID`_ corresponds to the _externalId_.
>

```powershell
$splatParams = @{
    Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/xml/getUsers"
    Method     = 'GET'
    Headers    = @{'Content-Type' = 'application/x-www-form-urlencoded' }
    Body       = @{ "customerID" = $($actionContext.Configuration.CustomerID); "$correlationField" = "$correlationValue" }
    WebSession = $sessionContext.Session
}
$response = Invoke-RestMethod @splatParams -Verbose:$false
```

### Reboarding

If a user account is removed using the _delete_ lifecycle action, it will be permanently deleted from _NokiLock_. As a result, a reboard will always result in a new account.

> [!NOTE]
> Even after the user account has been deleted, the associated _`cardID`_ will remain present within _NokiLock_. Keep in mind that its value is the 'externalId'.

### Number

The `number` property corresponds to the person's `externalId` and must include a leading zero for the first customer. This may need to be adjusted based on the specific requirements of each customer.

### CardID

The `cardID` property corresponds to the person's `externalId` and must include a leading zero for the first customer. This may need to be adjusted based on the specific requirements of each customer.

### UserID or: `id`

Both the _modifyUser_ and _removeUser_ SOAP actions, require the `userID` to be present in the update body. The value should be the `id` of the user account within _NokiLock_.

### Role

The `role` is hardcoded to the value of _student_.

### CustomerID / CustomerName

Both the `CustomerID` and `CustomerName` are required in the connection configuration and must be retrieved from the _NokiLock_ API using the following code:

```powershell
# Config
$actionContext.Configuration = @{
    UserName = ''
    Password = ''
    BaseUrl  = ''
}

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Connect-NokiLockWebService {
    [CmdletBinding()]
    param (
        [Parameter()]
        $UserName,

        [Parameter()]
        $Password
    )

    $challengeSaltSession = Get-NokiLockChallengeSaltSession -UserName $UserName
    $sha256Response = ConvertTo-NokiLockSha256Hash -Password $Password -Challenge $challengeSaltSession.Challenge -Salt $challengeSaltSession.Salt

    $splatLoginStagetwoParams = @{
        Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/json/loginStageTwo"
        Method     = 'POST'
        Headers    = @{'Content-Type' = 'application/x-www-form-urlencoded' }
        Body       = @{
            'username' = $UserName
            'response' = $sha256Response
        }
        WebSession = $challengeSaltSession.Session
    }
    # Only return the actual status (success or failed). In case of a failure, no error messages are returned
    $response = Invoke-RestMethod @splatLoginStageTwoParams -Verbose:$false
    if ($response.lockerApi.function.return.value -eq 'success') {
        Write-Information "NokiLock login: $($response.lockerApi.function.return.value)"
    }
    else {
        throw [System.Exception]::new("LockerAPI error: Login failed. Make sure your credentials are correct")
    }
    Write-Output $challengeSaltSession
}

function Get-NokiLockChallengeSaltSession {
    [CmdletBinding()]
    param (
        [Parameter()]
        $UserName
    )

    $splatLoginStageOneParams = @{
        Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/json/loginStageOne"
        Method     = 'POST'
        Headers    = @{'Content-Type' = 'application/x-www-form-urlencoded' }
        Body       = @{ 'username' = $UserName }
        WebSession = $webSession
    }
    # always returns a response/return even if the userName is incorrect
    $response = Invoke-RestMethod @splatLoginStageOneParams -Verbose:$false
    $challengeSaltSession = @{
        Salt      = ($response.lockerApi.function.return | Where-Object { $_.Name -eq 'salt' }).value
        Challenge = ($response.lockerApi.function.return | Where-Object { $_.Name -eq 'challenge' }).value
        Session   = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    }
    Write-Output $challengeSaltSession
}

function Disconnect-NokiLockWebService {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $NokiLockSession
    )

    $splatLogoutParams = @{
        Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/json/logout"
        Method     = 'POST'
        WebSession = $NokiLockSession
    }
    $response = Invoke-RestMethod @splatLogoutParams -Verbose:$false
    if ($response.lockerApi.function.type -eq 'response') {
        Write-Information "NokiLock logout: $($response.lockerApi.function.return.value)"
    }
    else {
        throw [System.Exception]::new("LockerAPI error: $($response.LockerAPI.error.message)")
    }
}

function ConvertTo-NokiLockSha256Hash {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Password,

        [Parameter()]
        [string]
        $Challenge,

        [Parameter()]
        [string]
        $Salt
    )

    $cryptoprovider = [System.Security.Cryptography.SHA256CryptoServiceProvider]::new()
    $cryptoprovider.Initialize()

    [byte[]] $passwordHashBytes = $cryptoprovider.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password + $Salt))
    $hashStringBuilder = [System.Text.StringBuilder]::new()
    foreach ($byte in $passwordHashBytes) {
        $null = $hashStringBuilder.Append($byte.ToString('x2'))
    }

    $passwordhHashstring = $hashStringBuilder.ToString()
    [byte[]] $Responsebytes = $cryptoprovider.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($passwordhHashstring + $Challenge))
    $finalHashStringBuilder = [System.Text.StringBuilder]::new()
    foreach ($byte in $Responsebytes) {
        $null = $finalHashStringBuilder.Append($byte.ToString('x2'))
    }

    $sha256Response = $finalHashStringBuilder.ToString()
    Write-Output $sha256Response
}
#endregion
try {
    Write-Information "Connecting to NokiLock webservice: $($actionContext.Configuration.BaseUrl)"
    $sessionContext = Connect-NokiLockWebService -UserName $actionContext.Configuration.UserName -Password $actionContext.Configuration.Password
    $splatParams = @{
        Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/xml/getCustomers"
        Method     = 'GET'
        Headers    = @{'Content-Type' = 'application/x-www-form-urlencoded' }
        Body       = @{ "customerID" = $($actionContext.Configuration.CustomerID) }
        WebSession = $sessionContext.Session
    }
    $response = Invoke-RestMethod @splatParams -Verbose:$false
    Write-Output $response.LockerAPI.function.return.customer
}
catch {
        $ex = $PSItem
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
}
finally {
    try {
        Disconnect-NokiLockWebService -NokiLockSession $sessionContext.Session
    }
    catch {
        $ex = $PSItem
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}
```

Version _1.0.0_ of the connector supports only **1** customer. If your implementation requires handling multiple customers, changes to the code will be necessary.

### Concurrent sessions

_NokiLock_ uses a __login__ and __logout__ SOAP action. The __logout__ function will __only__ terminate the session created during the currently running lifecycle action. It does not affect any other active sessions, even if they were initiated using the same credentials.

This indicates that session concurrency does not appear to be necessary.

## Development resources

### API endpoints

The following endpoints are used by the connector

| Endpoint            | Description               |
| ------------------- | ------------------------- |
| /rpc/xml/getUser    | Retrieve user information |
| /rpc/xml/addUser    | Add new user user         |
| /rpc/xml/modifyUser | Modify existing user      |
| /rpc/xml/removeUser | Remove existing user      |

### API documentation

Not available.

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
