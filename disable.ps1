####################################################
# HelloID-Conn-Prov-Target-NokiLock-Students-Disable
# PowerShell V2
####################################################

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
        userID                 = $NokiLockAccountObject.id
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
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    Write-Information "Connecting to NokiLock webservice: $($actionContext.Configuration.BaseUrl)"
    $sessionContext = Connect-NokiLockWebService -UserName $actionContext.Configuration.UserName -Password $actionContext.Configuration.Password

    Write-Information 'Verifying if a NokiLock-Students account exists'
    $splatParams = @{
        Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/xml/getUsers"
        Method     = 'GET'
        Headers    = @{'Content-Type' = 'application/x-www-form-urlencoded' }
        Body       = @{ "customerID" = $($actionContext.Configuration.CustomerID); "cardID" = "$($actionContext.References.Account)" }
        WebSession = $sessionContext.Session
    }
    $response = Invoke-RestMethod @splatParams -Verbose:$false
    if ($response.LockerApi.function.return.user) {
        $nokiLockAccountObject = $response.LockerApi.function.return.user
        $correlatedAccount = ConvertTo-HelloIDAccountObject -NokiLockAccountObject $nokiLockAccountObject
        $outputContext.PreviousData = $correlatedAccount
    }
    elseif ($response.LockerAPI.function.return.items -eq 0) {
        $correlatedAccount = $null
    }
    else {
        throw [System.Exception]::new("LockerAPI error: $($response.LockerAPI.error.message)")
    }

    if ($null -ne $correlatedAccount) {
        $action = 'DisableAccount'
    }
    else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'DisableAccount' {
            $body = @{
                "customerID" = $actionContext.Configuration.CustomerID
            }
            foreach ($prop in $correlatedAccount.PSObject.Properties) {
                $body[$prop.Name] = $prop.Value
            }

            $body.blocked = 'true'

            $splatUpdateParams = @{
                Uri        = "$($actionContext.Configuration.BaseUrl)/rpc/xml/modifyUser"
                Method     = 'POST'
                Headers    = @{'Content-Type' = 'application/x-www-form-urlencoded' }
                Body       = $body
                WebSession = $sessionContext.Session
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Disabling NokiLock-Students account with accountReference: [$($actionContext.References.Account)]"
                $response = Invoke-RestMethod @splatUpdateParams -Verbose:$false
                if ($response.LockerAPI.error.message) {
                    throw [System.Exception]::new("LockerAPI error: $($response.LockerAPI.error.message)")
                }
            }
            else {
                Write-Information "[DryRun] Disable NokiLock-Students account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'Disable account was successful'
                    IsError = $false
                })
            break
        }

        'NotFound' {
            Write-Information "NokiLock-Students account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "NokiLock-Students account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                    IsError = $false
                })
            break
        }
    }
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    $auditMessage = "Could not disable NokiLock-Students account. Error: $($_.Exception.Message)"
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