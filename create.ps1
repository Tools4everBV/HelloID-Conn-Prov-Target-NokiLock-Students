##################################################
# HelloID-Conn-Prov-Target-NokiLock-Student-Create
# PowerShell V2
##################################################

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

function ConvertTo-HelloIDAccountObject {
    [CmdletBinding()]
    param (
        $NokiLockAccountObject
    )

    $helloIDAccountObject = [PSCustomObject]@{
        id                     = $NokiLockAccountObject.id
        cardID                 = $NokiLockAccountObject.cardID
        number                 = $NokiLockAccountObject.number
        group                  = $NokiLockAccountObject.group
        surName                = $NokiLockAccountObject.surName
        firstName              = $NokiLockAccountObject.firstName
        middleName             = $NokiLockAccountObject.middleName
        role                   = $NokiLockAccountObject.role
        notes                  = $NokiLockAccountObject.notes
        blocked                = 'true'
        unfixedLockerLeaseTime = $NokiLockAccountObject.unfixedLockerLeaseTime
        emailAddress           = $NokiLockAccountObject.emailAddress
    }

    Write-Output $helloIDAccountObject
}
#endregion
try {
    # Initial Assignments
    $outputContext.AccountReference = 'Not available'

    Write-Information "Connecting to NokiLock webservice: $($actionContext.Configuration.BaseUrl)"
    $sessionContext = Connect-NokiLockWebService -UserName $actionContext.Configuration.UserName -Password $actionContext.Configuration.Password

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.AccountField
        $correlationValue = $actionContext.CorrelationConfiguration.AccountFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }

        $splatParams = @{
            Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/xml/getUsers"
            Method     = 'GET'
            Headers    = @{'Content-Type' = 'application/x-www-form-urlencoded' }
            Body       = @{ "customerID" = $($actionContext.Configuration.CustomerID); "$correlationField" = "$correlationValue" }
            WebSession = $sessionContext.Session
        }
        $response = Invoke-RestMethod @splatParams -Verbose:$false
        if ($response.LockerApi.function.return.user) {
            $nokiLockAccountObject = $response.LockerApi.function.return.user
            $correlatedAccount = ConvertTo-HelloIDAccountObject -NokiLockAccountObject $nokiLockAccountObject
        }
        elseif ($response.LockerAPI.function.return.items -eq 0) {
            $correlatedAccount = $null
        }
        else {
            throw [System.Exception]::new("LockerAPI error: $($response.LockerAPI.error.message)")
        }
    }

    if ($correlatedAccount.Count -eq 0) {
        $action = 'CreateAccount'
    }
    elseif ($null -ne $correlatedAccount) {
        $action = 'CorrelateAccount'
    }
    elseif ($correlatedAccount.Count -gt 1) {
        throw "Multiple accounts found for person where $correlationField is: [$correlationValue]"
    }

    # Process
    switch ($action) {
        'CreateAccount' {
            $body = @{
                "customerID" = $actionContext.Configuration.CustomerID
            }
            foreach ($prop in $actionContext.Data.PSObject.Properties) {
                $body[$prop.Name] = $prop.Value
            }
            $splatCreateParams = @{
                Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/xml/addUser"
                Method     = 'POST'
                Headers    = @{'Content-Type' = 'application/x-www-form-urlencoded' }
                Body       = $body
                WebSession = $sessionContext.Session
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information 'Creating and correlating NokiLock-Student account'
                $response = Invoke-RestMethod @splatCreateParams -Verbose:$false
                if ($response.LockerAPI.error.message) {
                    throw [System.Exception]::new("LockerAPI error: $($response.LockerAPI.error.message)")
                }
                $userID = ($response.LockerAPI.function.return | Where-Object { $_.name -eq 'userID' }).value

                Write-Information 'Retrieving NokiLock account after initial create'
                $splatParams = @{
                    Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/xml/getUsers"
                    Method     = 'GET'
                    Headers    = @{'Content-Type' = 'application/x-www-form-urlencoded' }
                    Body       = @{ "customerID" = $($actionContext.Configuration.CustomerID); "$correlationField" = "$correlationValue" }
                    WebSession = $sessionContext.Session
                }
                $response = Invoke-RestMethod @splatParams -Verbose:$false
                if ($response.LockerApi.function.return.user) {
                    $nokiLockAccountObject = $response.LockerApi.function.return.user
                    $createdAccount = ConvertTo-HelloIDAccountObject -NokiLockAccountObject $nokiLockAccountObject
                }
                $outputContext.Data = $createdAccount
                $outputContext.AccountReference = $createdAccount.cardID
            }
            else {
                Write-Information '[DryRun] Create and correlate NokiLock-Student account, will be executed during enforcement'
            }
            $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]"
            break
        }

        'CorrelateAccount' {
            Write-Information 'Correlating NokiLock-Student account'
            $outputContext.Data = $correlatedAccount
            $outputContext.AccountReference = $correlatedAccount.cardID
            $outputContext.AccountCorrelated = $true
            $auditLogMessage = "Correlated account: [$($outputContext.AccountReference)] on field: [$($correlationField)] with value: [$($correlationValue)]"
            break
        }
    }

    $outputContext.success = $true
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = $action
            Message = $auditLogMessage
            IsError = $false
        })
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    $auditMessage = "Could not create or correlate NokiLock-Student account. Error: $($ex.Exception.Message)"
    Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
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