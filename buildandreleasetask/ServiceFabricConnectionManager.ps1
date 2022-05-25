# See Tasks\AzurePowerShell\AzurePowerShell.ps1 for the original inspiration

Trace-VstsEnteringInvocation $MyInvocation
Import-VstsLocStrings "$PSScriptRoot\Task.json"

# Get inputs.
$serviceConnectionName = Get-VstsInput -Name serviceConnectionName -Require
$scriptType = 'InlineScript' #Get-VstsInput -Name ScriptType -Require
$scriptPath = "" #Get-VstsInput -Name ScriptPath
$scriptInline = Get-VstsInput -Name Inline
$scriptArguments = '' #Get-VstsInput -Name ScriptArguments
$azureSubscriptionName = Get-VsTsInput -Name azureSubscriptionEndpoint

write-host "serviceConnectionName: $serviceConnectionName"
write-host "azureSubscriptionName: $azureSubscriptionName"

$certificate = $null
$connectedServiceEndpoint = Get-VstsEndpoint -Name $serviceConnectionName -Require
$azureSubscriptionEndpoint = Get-VstsEndpoint -Name $azureSubscriptionName

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
            $certificate = Connect-ServiceFabricClusterFromServiceEndpoint -ClusterConnectionParameters $clusterConnectionParameters -ConnectedServiceEndpoint $connectedServiceEndpoint
        }
        catch {
            write-host "Connect-ServiceFabricClusterFromServiceEndpoint exception: $($exception | out-string)"
            Publish-Telemetry -TaskName 'ServiceFabricPowerShell' -OperationId $global:operationId  -ErrorData $_
            #todo remove #throw
        }

        # Trace the expression as it will be invoked.
        If ($scriptType -eq "InlineScript") {
            $tempFileName = [guid]::NewGuid().ToString() + ".ps1";
            write-host "using inlinescript"
            $scriptPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $tempFileName);
        ($scriptInline | Out-File $scriptPath)
        }

        $scriptCommand = "& '$($scriptPath.Replace("'", "''"))' $scriptArguments"
        Remove-Variable -Name scriptArguments

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
            Remove-Variable -Name scriptCommand
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
        If ($scriptType -eq "InlineScript" -and $scriptPath -and (Test-Path -LiteralPath $scriptPath)) {
            Remove-Item -LiteralPath $scriptPath -Force -ErrorAction 'SilentlyContinue' | Out-Null
        }

        #Remove-Variable -Name scriptPath

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

function update-thumbprint() {
    write-host "starting update-thumbprint"
    $error.Clear()
    $ErrorActionPreference = "Continue"
    $verbosePreference = $debugpreference = 'continue'
    $psversiontable
    [environment]::getenvironmentvariables()

    write-host "connectedServiceEndpoint: $($connectedServiceEndpoint | convertto-json)"
    $serverThumbprint = $connectedServiceEndpoint.Auth.Parameters.servercertthumbprint
    write-host "cluster connection server certificate thumbprint: $serverThumbprint"
    write-host "cert length: $($connectedServiceEndpoint.Auth.Parameters.Certificate.length)"

    if ($azureSubscriptionName) {
        write-host "check for managed cluster server thumbprint"

        if ($azureSubscriptionEndpoint.Auth.Scheme -ne "ServicePrincipal") {
            # throw (Get-VstsLocString -Key UnsupportedARMAuthScheme -ArgumentList $connectedServiceEndpoint.Auth.Scheme)
        }
        write-host "azureSubscriptionEndpoint: $($azureSubscriptionEndpoint | convertto-json)"
        $clientId = $azureSubscriptionEndpoint.Auth.Parameters.ServicePrincipalId
        write-host "clientId: $clientId"
        $clientSecret = $azureSubscriptionEndpoint.Auth.Parameters.ServicePrincipalKey
        $isPasswordEncrypted = $false
    }
    write-host "rest logon result: $($result|convertto-json)"
    $error.clear()
    $resource = "https://management.azure.com/"
    $tenantId = $azureSubscriptionEndpoint.Auth.Parameters.tenantId
    $endpoint = "$($azureSubscriptionEndpoint.Data.environmentAuthorityUrl)/$tenantId/oauth2/token"
    $subscriptionId = $azureSubscriptionEndpoint.Data.subscriptionId

    $Body = @{
        'resource'      = ([system.web.httpUtility]::UrlDecode($resource))
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

    write-host ($body | convertto-json)
    write-host ($params | convertto-json)
    write-host $clientSecret
    $error.Clear()

    $result = Invoke-RestMethod @params -Verbose -Debug
    write-host "result: $($result | convertto-json)"
    write-host "rest logon finished"
    $result

    $filter = "resourceType eq 'Microsoft.ServiceFabric/managedclusters'"
    $expand = ''
    $top = 100
    $header = @{
        'Authorization' = "Bearer $($result.access_token)"
    }
    $url = "https://management.azure.com/subscriptions/$subscriptionId/resources?`$filter=$filter&`$expand=$expand&`$top=$top&api-version=2022-05-01"

    $url
    $result = Invoke-RestMethod -Method Get -uri $url -Headers $header -Verbose -Debug
    $result | convertto-json

    $url = "https://management.azure.com/$($result.value.id)?api-version=2021-05-01"

    $url
    $result = Invoke-RestMethod -Method Get -uri $url -Headers $header
    $result | convertto-json

    $fqdn = $result.properties.fqdn
    write-host "fqdn $fqdn"
    $clusterCertificateThumbprint = $result.properties.clusterCertificateThumbprints[0]
    write-host "clusterCertificateThumbprint $clusterCertificateThumbprint"
    write-host "rest logon finished"

    if ($serverThumbprint -eq $clusterCertificateThumbprint) {
        write-host "certificate thumbprints match. returning."
        return
    }

    write-host "certificate thumbprints do not match. attempting to update connection"
    try {
        $connectedServiceEndpoint.Auth.Parameters.servercertthumbprint = $clusterCertificateThumbprint
        write-host "set directly"
    }
    catch {
        write-host "cant set directly"
    }
    # update env?
    # https://docs.microsoft.com/en-us/azure/devops/pipelines/process/set-variables-scripts?view=azure-devops&tabs=powershell#set-an-output-variable-for-use-in-future-stages
    #write-host "##vso[task.setvariable variable="
    #
    # get service fabric service connection
    #
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
    write-host ($parameters | convertto-json)
    write-host "invoke-restMethod -uri $([system.web.httpUtility]::UrlDecode($url)) -headers $adoAuthHeader"

    $result = invoke-RestMethod @parameters
    write-host "json result: $($result | convertto-json)"
    write-host "authenticated to ado rest"

    $serviceConnection = $result.value
    $serviceConnectionThumbprint = $serviceConnection.authorization.parameters.servercertthumbprint
    write-host "service connection thumbprint:$serviceConnectionThumbprint" -ForegroundColor Cyan
    $serviceConnectionId = $serviceConnection.Id

    $url += "/$($serviceConnectionId)?api-version=7.1-preview.4"
    write-host "servercertthumbprint = $serverThumbprint"
    $p = @{
        certLookup           = $connectedServiceEndpoint.Auth.Parameters.CertLookup
        servercertthumbprint = $clusterCertificateThumbprint
        certificate          = $connectedServiceEndpoint.Auth.Parameters.Certificate
    }
    write-host "p $($p|convertto-json)"
    $serviceConnection.authorization.parameters = $p
    $parameters = @{
        Uri         = $url
        Method      = 'PUT'
        Headers     = $adoAuthHeader
        Erroraction = 'continue'
        Body        = ($serviceConnection | convertto-json -compress -depth 99)
    }
    write-host ($parameters | convertto-json)
    write-host "invoke-restMethod -uri $([system.web.httpUtility]::UrlDecode($url)) -headers $adoAuthHeader"
    $error.clear()
    $result = invoke-RestMethod @parameters
    $result | Format-List *
    write-host ($result | convertto-json -Depth 99)
    if ($error) {
        write-error "error updating service endpoint $($error)"
    }
    else {
        write-host "endpoint updated successfully"
    }
    write-host "finished update-thumbprint"
}

main
# We don't call Trace-VstsLeavingInvocation at the end because that command was removed prior to calling the user script.