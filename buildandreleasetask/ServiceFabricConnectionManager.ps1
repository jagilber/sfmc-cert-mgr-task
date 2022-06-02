# See Tasks\AzurePowerShell\AzurePowerShell.ps1 for the original inspiration

Trace-VstsEnteringInvocation $MyInvocation
Import-VstsLocStrings "$PSScriptRoot\Task.json"

# Get inputs.
$serviceConnectionName = Get-VstsInput -Name serviceConnectionName -Require
$scriptPath = "" #Get-VstsInput -Name ScriptPath
$scriptInline = Get-VstsInput -Name Inline
$azureSubscriptionName = Get-VsTsInput -Name azureSubscriptionEndpoint

write-host "serviceConnectionName: $serviceConnectionName"
write-host "azureSubscriptionName: $azureSubscriptionName"

$certificate = $null
$global:connectedServiceEndpoint = Get-VstsEndpoint -Name $serviceConnectionName -Require
$global:azureSubscriptionEndpoint = Get-VstsEndpoint -Name $azureSubscriptionName
$armAuthResourceUrl = 'https://management.azure.com'
$global:clusterCertificateThumbprint = $null
$global:adoCurrentServerThumbprint = $null

function main() {
    try {
        write-host "starting"
        update-thumbprint

        # Initialize Service Fabric.
        Import-Module $PSScriptRoot\ps_modules\ServiceFabricHelpers

        $global:operationId = $SF_Operations.Undefined
        $clusterConnectionParameters = @{}

        try {
            write-host "Connect-ServiceFabricClusterFromServiceEndpoint"
            $certificate = Connect-ServiceFabricClusterFromServiceEndpoint -ClusterConnectionParameters $clusterConnectionParameters -ConnectedServiceEndpoint $global:connectedServiceEndpoint
        }
        catch {
            write-host "Connect-ServiceFabricClusterFromServiceEndpoint exception: $($exception | out-string)"
            Publish-Telemetry -TaskName 'ServiceFabricPowerShell' -OperationId $global:operationId  -ErrorData $_
            #todo remove #throw
        }

        # Trace the expression as it will be invoked.
        If ($scriptInline) {
            $tempFileName = [guid]::NewGuid().ToString() + ".ps1";
            write-host "using inlinescript"
            $scriptPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $tempFileName);
        ($scriptInline | Out-File $scriptPath)
        }

        $scriptCommand = "& '$($scriptPath.Replace("'", "''"))'"

        # Remove all commands imported from VstsTaskSdk, other than Out-Default.
        # Remove all commands imported from ServiceFabricHelpers.
        Get-ChildItem -LiteralPath function: |
        Where-Object {
        ($_.ModuleName -eq 'VstsTaskSdk' -and $_.Name -ne 'Out-Default') -or
        ($_.Name -eq 'Invoke-VstsTaskScript') -or
        ($_.ModuleName -eq 'ServiceFabricHelpers' )
        } |
        Remove-Item

        # For compatibility with the legacy handler implementation, set the error action
        # preference to continue. An implication of changing the preference to Continue,
        # is that Invoke-VstsTaskScript will no longer handle setting the result to failed.
        $global:ErrorActionPreference = 'Continue'

        # Run the user's script. Redirect the error pipeline to the output pipeline to enable
        # a couple goals due to compatibility with the legacy handler implementation:
        # 1) STDERR from external commands needs to be converted into error records. Piping
        #    the redirected error output to an intermediate command before it is piped to
        #    Out-Default will implicitly perform the conversion.
        # 2) The task result needs to be set to failed if an error record is encountered.
        #    As mentioned above, the requirement to handle this is an implication of changing
        #    the error action preference.
    ([scriptblock]::Create($scriptCommand)) |
        ForEach-Object {
            #Remove-Variable -Name scriptCommand
            Write-Host "##[command]$_"
            . $_ 2>&1
        } |
        ForEach-Object {
            # Put the object back into the pipeline. When doing this, the object needs
            # to be wrapped in an array to prevent unraveling.
            , $_

            # Set the task result to failed if the object is an error record.
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                "##vso[task.complete result=Failed]"
            }
        }
    }
    catch {
        if ($null -ne $certificate) {
            $thumbprint = $certificate.Thumbprint
            if (!(Test-Path "Cert:\CurrentUser\My\$thumbprint")) {
                Write-Warning (Get-VstsLocString -Key CertNotPresentInLocalStoreWarningMsg -ArgumentList $thumbprint)
            }
        }
        #todo remove #throw
    }
    Finally {
        If ($scriptInline -and $scriptPath -and (Test-Path -LiteralPath $scriptPath)) {
            Remove-Item -LiteralPath $scriptPath -Force -ErrorAction 'SilentlyContinue' | Out-Null
        }

        # Can't use Remove-ClientCertificate as we removed all funcitons above
        try {
            if ($null -ne $certificate) {
                $thumbprint = $certificate.Thumbprint
                if (Test-Path "Cert:\CurrentUser\My\$thumbprint") {
                    Remove-Item "Cert:\CurrentUser\My\$thumbprint" -Force
                }
            }
        }
        catch {
            Write-Warning $_
        }
    }
}

function confirm-SFMCClusterServerThumbprintCurrent($armConnection, $serviceConnectionFqdn) {
    write-host "searching for all managed cluster resources"
    $filter = "resourceType eq 'Microsoft.ServiceFabric/managedclusters'"
    #$expand = ''
    #$top = 100
    $header = @{'Authorization' = "Bearer $($armConnection.access_token)" }
    $subscriptionId = $global:azureSubscriptionEndpoint.Data.subscriptionId

    $url = "$armAuthResourceUrl/subscriptions/$subscriptionId/resources?`$filter=$filter&api-version=2022-05-01"
    write-host "resource search request: $url"
    $result = Invoke-RestMethod -Method Get -uri $url -Headers $header -Verbose -Debug
    write-host "resource search result: $($result | convertto-json)"

    write-host "searching for managed cluster with fqdn: $serviceConnectionFqdn"
    foreach ($cluster in @($result.value)) {
        $url = "$armAuthResourceUrl/$($cluster.id)?api-version=2021-05-01"
        write-host "resource request: $url"
        $resource_result = Invoke-RestMethod -Method Get -uri $url -Headers $header
        write-host "resource result: $($resource_result | convertto-json)"

        $fqdn = $resource_result.properties.fqdn
        write-host "checking fqdn: $fqdn"

        if ($serviceConnectionFqdn -imatch $fqdn) {
            write-host "cluster fqdn: $fqdn matches service fabric service connection url: $serviceConnectionFqdn"
            $global:clusterCertificateThumbprint = $resource_result.properties.clusterCertificateThumbprints[0]
            write-host "clusterCertificateThumbprint $global:clusterCertificateThumbprint"
    
            if ($global:adoCurrentServerThumbprint -eq $global:clusterCertificateThumbprint) {
                write-host "certificate thumbprints match. returning."
                return $true
            }
            else {
                write-host "certificates do not match returning false"
                return $false
            }
        }
        else {
            write-host "cluster fqdn: $fqdn does not match service fabric service connection url: $serviceConnectionFqdn"
            continue
        }
    }

    if (!$global:clusterCertificateThumbprint) {
        throw (Get-VstsLocString -Key ARMSFMCNotFound -ArgumentList $serviceConnectionFqdn)
    }
    return $false
}

function get-ADOSFConnection() {
    write-host "getting service fabric service connection"
    $url = "$env:SYSTEM_COLLECTIONURI/$env:SYSTEM_TEAMPROJECTID/_apis/serviceendpoint/endpoints"
    $adoAuthHeader = @{
        'authorization' = "Bearer $env:accessToken"
        'content-type'  = 'application/json'
    }
    $bodyParameters = @{
        'type'          = 'servicefabric'
        'api-version'   = '7.1-preview.4'
        'endpointNames' = $env:connectionName
    }
    $parameters = @{
        Uri         = $url
        Method      = 'GET'
        Headers     = $adoAuthHeader
        Erroraction = 'continue'
        Body        = $bodyParameters
    }
    write-host "ado connection parameters: $($parameters | convertto-json)"
    write-host "invoke-restMethod -uri $([system.web.httpUtility]::UrlDecode($url)) -headers $adoAuthHeader"

    $error.clear()
    $result = invoke-RestMethod @parameters
    write-host "ado connection result: $($result | convertto-json)"
    if ($error) {
        throw (Get-VstsLocString -Key ADOAuthFailure -ArgumentList ($result | convertto-json))
    }
    return $result
}

function get-ARMConnection() {
    write-host "getting arm connection"

    if ($global:azureSubscriptionEndpoint.Auth.Scheme -ne "ServicePrincipal") {
        throw (Get-VstsLocString -Key UnsupportedARMAuthScheme -ArgumentList $global:connectedServiceEndpoint.Auth.Scheme)
    }
    write-host "azureSubscriptionEndpoint: $($global:azureSubscriptionEndpoint | convertto-json)"
    $clientId = $global:azureSubscriptionEndpoint.Auth.Parameters.ServicePrincipalId
    write-host "clientId: $clientId"
    $clientSecret = $global:azureSubscriptionEndpoint.Auth.Parameters.ServicePrincipalKey
    write-host "clientsecret length: $($clientSecret.length)"
    # authenticating to arm
    $error.clear()
    $tenantId = $global:azureSubscriptionEndpoint.Auth.Parameters.tenantId
    $endpoint = "$($global:azureSubscriptionEndpoint.Data.environmentAuthorityUrl)$tenantId/oauth2/token"

    $Body = @{
        'resource'      = $armAuthResourceUrl
        'client_id'     = $clientId
        'grant_type'    = 'client_credentials'
        'client_secret' = $clientSecret
    }
    $params = @{
        ContentType = 'application/x-www-form-urlencoded'
        Headers     = @{'accept' = '*/*' }
        Body        = $Body
        Method      = 'Post'
        URI         = $endpoint
    }

    write-host "arm rest logon request: $($params | convertto-json)"
    $error.Clear()

    $result = Invoke-RestMethod @params -Verbose -Debug
    write-host "arm rest logon result: $($result | convertto-json)"

    if ($error) {
        throw (Get-VstsLocString -Key ARMAuthFailure -ArgumentList ($result | convertto-json))
    }

    return $result
}

function update-ADOSFConnection($adoConnection, $auth) {
    write-host "updating ado sf connection"
    # update env?
    # https://docs.microsoft.com/en-us/azure/devops/pipelines/process/set-variables-scripts?view=azure-devops&tabs=powershell#set-an-output-variable-for-use-in-future-stages
    # write-host "##vso[task.setvariable variable="
    $error.clear()
    try {
        write-host "##vso[task.setvariable variable=ENDPOINT_AUTH_$serviceConnectionName]$auth"
        if ($error) {
            write-warning "error updating env var: $($error | out-string)"
        }

        #$base64after = [convert]::ToBase64String([text.encoding]::UTF8.GetBytes([environment]::getenvironmentvariable("ENDPOINT_AUTH_$serviceConnectionName")))
        #write-host "env var after:`r`n$base64after"
    }
    catch { write-host "exception $($error | out-string)" }

    $serviceConnection = $adoConnection.value
    $serviceConnectionThumbprint = $serviceConnection.authorization.parameters.servercertthumbprint
    write-host "service connection thumbprint:$serviceConnectionThumbprint" -ForegroundColor Cyan
    $serviceConnectionId = $serviceConnection.Id
    $url = "$env:SYSTEM_COLLECTIONURI/$env:SYSTEM_TEAMPROJECTID/_apis/serviceendpoint/endpoints"
    $url += "/$($serviceConnectionId)?api-version=7.1-preview.4"
    write-host "servercertthumbprint = $global:adoCurrentServerThumbprint"
    $authorizationParameters = @{
        certLookup           = $global:connectedServiceEndpoint.Auth.Parameters.CertLookup
        servercertthumbprint = $global:clusterCertificateThumbprint
        certificate          = $global:connectedServiceEndpoint.Auth.Parameters.Certificate
        certificatePassword  = $global:connectedServiceEndpoint.Auth.Parameters.CertificatePassword
    }

    write-host "authorizationParameters: $($authorizationParameters|convertto-json)"
    $serviceConnection.authorization.parameters = $authorizationParameters

    $adoAuthHeader = @{
        'authorization' = "Bearer $env:accessToken"
        'content-type'  = 'application/json'
    }

    $parameters = @{
        Uri         = $url
        Method      = 'PUT'
        Headers     = $adoAuthHeader
        Erroraction = 'continue'
        Body        = $serviceConnection
    }
    write-host "new service connection parameters: $($parameters | convertto-json)"
    write-host "invoke-restMethod -uri $([system.web.httpUtility]::UrlDecode($url)) -headers $adoAuthHeader"
    
    $error.clear()
    $result = invoke-RestMethod @parameters
    write-host "ado update result: $($result | convertto-json)"

    if ($error) {
        write-error "error updating service endpoint $($error)"
        throw (Get-VstsLocString -Key ADOUpdateFailure -ArgumentList ($result | convertto-json))
    }
    else {
        write-host "endpoint updated successfully"
    }
}

function update-thumbprint() {
    write-host "starting update-thumbprint"
    $error.Clear()
    $ErrorActionPreference = $verbosePreference = $debugpreference = 'continue'
    write-host "psversiontable: $($psversiontable)"
    [environment]::getenvironmentvariables()

    write-host "connectedServiceEndpoint: $($global:connectedServiceEndpoint | convertto-json)"
    $serviceConnectionFqdn = $global:connectedServiceEndpoint.url.replace('tcp://', '')
    write-host "cluster connection service url: $serviceConnectionFqdn"

    $global:adoCurrentServerThumbprint = $global:connectedServiceEndpoint.Auth.Parameters.servercertthumbprint
    write-host "cluster connection server certificate thumbprint: $global:adoCurrentServerThumbprint"
    write-host "cert length: $($global:connectedServiceEndpoint.Auth.Parameters.Certificate.length)"
    write-host "checking for managed cluster server thumbprint"

    if ($azureSubscriptionName) {
        $armConnection = get-ARMConnection
    }
    else {
        write-warning ."ARM connection information not provided. returning."
        return
    }

    if ($serviceConnectionName) {
        if ((confirm-SFMCClusterServerThumbprintCurrent -armConnection $armConnection -serviceConnectionFqdn $serviceConnectionFqdn)) {
            return
        }
    }
    else {
        write-warning ."SF connection information not provided. returning."
        return
    }

    write-host "certificate thumbprints do not match. attempting to update connection"
    $adoSFConnection = get-ADOSFConnection 
    $global:connectedServiceEndpoint.Auth.Parameters.servercertthumbprint = $global:clusterCertificateThumbprint
    $global:connectedServiceEndpointAuth = $global:connectedServiceEndpoint.Auth | convertto-json -depth 99 -Compress
    write-host "new auth config: $global:connectedServiceEndpointAuth"
    update-ADOSFConnection -adoConnection $adoSFConnection -auth $global:connectedServiceEndpointAuth
    write-host "finished update-thumbprint"
}

try {
    main
}
catch {
    write-warning "main exception $($_)`r`n$($error | out-string)"
}
# We don't call Trace-VstsLeavingInvocation at the end because that command was removed prior to calling the user script.