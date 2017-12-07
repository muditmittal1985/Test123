param(
    [Parameter(Mandatory=$true)][string]$parameterFile,
    [Parameter(Mandatory=$true)][string]$collection,
    [Parameter(Mandatory=$true)][string]$project,
    [Parameter(Mandatory=$true)][string]$repository,
    [Parameter(Mandatory=$true)][string]$commit,
    [Parameter(Mandatory=$true)][string]$token,
    [string]$UpdateLinkedService,
    [switch]$FullDeploy
)

$ErrorActionPreference = 'Stop'

    Write-Output "Fetching Parameter File AbsolutePath"
    $parameterFile = & "$PSScriptRoot\Get-ParameterFilepath.ps1" -parameterFile $parameterFile
    Write-Output "Parameter File AbsolutePath: $parameterFile"

    Write-Host "Starting ADF Pipeline deployment`n"
    $parameters = (Get-Content -Path $parameterFile -Raw) | ConvertFrom-JSON
    $subscriptionId = $parameters.parameters.subscriptionId.value
    $tenantId = $parameters.parameters.tenantId.value
    $applicationId = $parameters.parameters.deploymentApplicationId.value
    $DataFactoryResourceGroup = $parameters.parameters.dataFactoryResourceGroupName.value
    $DataFactoryName = $parameters.parameters.dataFactoryName.value
    $Location = $parameters.parameters.Location.value
    $keyVaultName = $parameters.parameters.keyVaultName.value
    $GateWayName = $parameters.parameters.dataFactoryGatewayName.value
    $gatewayhost = $parameters.parameters.gatewayhost.value
    $gatewayhost = $gatewayhost.Replace("\","\\")
    $adlStoreName = $Parameters.parameters.adlStoreName.value

    $subscriptionId = $parameters.parameters.subscriptionId.value
    $sub = Select-AzureRmSubscription -SubscriptionId $subscriptionId
    Write-Output $sub

    $TemplateFolder = 'datafactory'
    $ScriptFolder = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
    $JsonTemplatePath = (Split-Path -Path $ScriptFolder -Parent) + "\DataIQ\$TemplateFolder"
    if(-not(Test-Path -Path $JsonTemplatePath)) {
        throw "Template path invalid: $JsonTemplatePath"
    }

    $JsonTemplateFiles = Get-ChildItem -Path "$JsonTemplatePath" -Recurse -ErrorAction Stop | ?{$_.Name -like "*.json"}
    $dataFactory = Get-AzureRmDataFactory -ResourceGroupName $DataFactoryResourceGroup -Name $DataFactoryName -ErrorAction SilentlyContinue
    if(-not($dataFactory)) {
        write-output "Cannot find Azure Data Factory $DataFactoryName"
        return
    }

    Write-Host "*****  $DataFactoryName Exist  *****`n"
    $AlreadyExistingLinkedServices = Get-AzureRmDataFactoryLinkedService -DataFactory $dataFactory
    $AlreadyExistingDataSets = Get-AzureRmDataFactoryDataset -DataFactory $dataFactory
    $AlreadyExistingPipelines = Get-AzureRmDataFactoryPipeline -DataFactory $dataFactory

    if(-not($FullDeploy)) {
        Write-Output "Fetching updates to Data sets and Pipelines if any"
        [string]$ReturnString = & "$ScriptFolder\Get-ModifiedFile.ps1" -collection $collection -project $project -repository $repository -commit $commit -token $token
        if($ReturnString) {
            $SplitFiles =@()
            $SplitFiles = $ReturnString.split(" ")
            $SplitFiles = $SplitFiles | ? {$_ -like "*.json"}
        }
        
        if($SplitFiles) {
            $AbsoluteFilePaths =@()
            ForEach($File in $SplitFiles) {
                $FileName = Split-Path -path $File -Leaf
                ForEach($Template in $JsonTemplateFiles.FullName) {
                    $TemplateName = Split-Path -path $Template -Leaf
                    if($FileName -eq $TemplateName) {
                        $AbsoluteFilePaths += $Template
                    }
                }
            
            }
            Write-Output "Deploying changes $($AbsoluteFilePaths.count)"
        }
        else {
            Write-Output "No changes in Data set and Pipeline"
        }
    }
    else {
        Write-Output "Deploying all Data sets and Pipelines"
        $AbsoluteFilePaths = $JsonTemplateFiles.FullName
        if(-not($AbsoluteFilePaths)) {
            throw "JSON Templates not found: $JsonTemplatePath"
        }
    }

    $DataSets = @()
    $Pipelines = @()
    ForEach($File in $AbsoluteFilePaths) {
        $FileContent = $null
        $FileContent = ConvertFrom-Json (Get-Content -Path $File -raw)
        if($FileContent.'$schema' -match 'DataFactory.Pipeline') { $Pipelines += $File }
        elseif($FileContent.'$schema' -match 'DataFactory.Table') { $DataSets += $File }
        else {}
    }
 
    Write-Output "Data Sets: $($DataSets.count)"
    Write-Output "Pipelines: $($Pipelines.count)"

    #########################################################################################################
    if((-not($AlreadyExistingLinkedServices | where {$_.LinkedServiceName -eq 'HDInsightLinkedService'})) -or ("HDInsightLinkedService" -eq $UpdateLinkedService)) {
        Write-Output "Creating linked service: HDInsightLinkedService"
        $TodayDate = [string](Get-Date -Format 'yyyy-MM-dd')
        $LinkedServiceFileName = "HDInsightLinkedService" + [string](Get-Date -Format ddMMYYmmhhss) + ".json"
        $ClusterName = $parameters.parameters.clusterName.value
        $ClusterAdmin = $parameters.parameters.clusterAdminLogin.value
        $keyVaultName = $parameters.parameters.keyVaultName.value
        $secret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $ClusterAdmin -ErrorAction SilentlyContinue
        $clusterAdminPassword = $secret.SecretValue
        $InsecurePassword = (New-Object PSCredential "$ClusterAdmin",$clusterAdminPassword).GetNetworkCredential().Password
        $clusterAdminPassword = $InsecurePassword
        $ClusterURI = "https://$ClusterName.azurehdinsight.net"

        Write-Host "*** Deploying HDInsight Linked Service ***"
        $HDInsightJsonContent = $null

$HDInsightJsonContent = "{
        `"name`": `"HDInsightLinkedService`",
        `"properties`": {
            `"description`": `"`",
            `"type`": `"HDInsight`",
            `"typeProperties`": {
            `"clusterUri`": `"$ClusterURI`",
            `"userName`": `"$ClusterAdmin`",
            `"password`": `"$clusterAdminPassword`",
            `"linkedServiceName`": `"Storage`"
        }
    },
  `"`$schema`": `"http://datafactories.schema.management.azure.com/internalschemas/$TodayDate/Microsoft.DataFactory.linkedservice.json`"
}"

        $HDInsightJsonContent | Out-File -FilePath "$JsonTemplatePath\$LinkedServiceFileName" -Encoding ascii -Force
        Start-Sleep -Seconds 5
        $LinkedServerTemplate = $null
        $LinkedServerTemplate = ConvertFrom-Json (Get-Content "$JsonTemplatePath\$LinkedServiceFileName" -Raw)
        New-AzureRmDataFactoryLinkedService -DataFactory $dataFactory -File "$JsonTemplatePath\$LinkedServiceFileName" -Force
        Start-Sleep -Seconds 2
        Remove-Item -Path "$JsonTemplatePath\$LinkedServiceFileName" -Force
    }


################################################## infoscoutsftp ################################################
if((-not($AlreadyExistingLinkedServices | where {$_.LinkedServiceName -eq 'infoscoutsftplinkedservice'})) -or ("infoscoutsftplinkedservice" -eq $UpdateLinkedService)) {
        Write-Output "Creating linked service: infoscoutsftplinkedservice"
        $TodayDate = [string](Get-Date -Format 'yyyy-MM-dd')
        $LinkedServiceFileName = "infoscoutsftplinkedservice" + [string](Get-Date -Format ddMMYYmmhhss) + ".json"

        $username = $parameters.parameters.infoscoutsftpUserName.value
        $KeyName = $parameters.parameters.infoscoutsftpKeyName.value
        $hubname = $DataFactoryName + "_hub"
        $secret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $KeyName -ErrorAction SilentlyContinue
        $SecurePassword = $secret.SecretValue
        $Password = (New-Object PSCredential "$KeyName",$SecurePassword).GetNetworkCredential().Password
        $TabssFTP = $null

$TabssFTP="{
    `"name`": `"infoscoutsftplinkedservice`",
    `"properties`": {
        `"hubName`": `"$hubname`",
        `"type`": `"Sftp`",
        `"typeProperties`": {
            `"host`": `"infoscout.brickftp.com`",
            `"authenticationType`": `"Basic`",
            `"username`": `"$username`",
            `"password`": `"$Password`",
            `"privateKeyPath`": `"`",
            `"skipHostKeyValidation`": true,
            `"hostKeyFingerprint`": `"`",
            `"gatewayName`": `"`",
            `"encryptedCredential`": `"`"
        }
    },
  `"`$schema`": `"http://datafactories.schema.management.azure.com/internalschemas/2015-09-01/Microsoft.DataFactory.linkedservice.json`"
}"

        $TabssFTP | Out-File -FilePath "$JsonTemplatePath\$LinkedServiceFileName" -Encoding ascii -Force
        Start-Sleep -Seconds 5
        $LinkedServerTemplate = $null
        $LinkedServerTemplate = ConvertFrom-Json (Get-Content "$JsonTemplatePath\$LinkedServiceFileName" -Raw)
        New-AzureRmDataFactoryLinkedService -DataFactory $dataFactory -File "$JsonTemplatePath\$LinkedServiceFileName" -Force
        Start-Sleep -Seconds 2
        Remove-Item -Path "$JsonTemplatePath\$LinkedServiceFileName" -Force
}

    ######################################### SQL DW Code ###################################################
if((-not($AlreadyExistingLinkedServices | where {$_.LinkedServiceName -eq 'SQLDW'})) -or ("SQLDW" -eq $UpdateLinkedService)) {
    Write-Output "Creating linked service: SQLDW"
    $TodayDate = [string](Get-Date -Format 'yyyy-MM-dd')
    $SQLCatalog = $parameters.parameters.sqlDataWarehouseName.value
    $sqlServerAdminLogin = $parameters.parameters.sqlServerAdminLogin.value
    $SQLSource = $parameters.parameters.sqlServerName.value
    $SQLSource += ".database.windows.net"

    $keyVaultName = $parameters.parameters.keyVaultName.value
    $secret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $sqlServerAdminLogin
    $sqlAdminPassword = $secret.SecretValue
    $InsecurePassword = (New-Object PSCredential "$sqlServerAdminLogin",$sqlAdminPassword).GetNetworkCredential().Password
    $sqlAdminPassword = $InsecurePassword
    $UserID = $sqlServerAdminLogin + "@" + $SQLSource
$SQLDW= "{
  `"name`": `"SqlDW`",
  `"properties`": {
    `"description`": `"`",
    `"type`": `"AzureSqlDW`",
    `"typeProperties`": {
      `"connectionString`": `"Data Source=tcp:$SQLSource,1433;Initial Catalog=$SQLCatalog;Integrated Security=False;User ID=$UserID;Password=$sqlAdminPassword;Connect Timeout=30;Encrypt=True`"
    }
  },
  `"`$schema`": `"http://datafactories.schema.management.azure.com/internalschemas/$TodayDate/Microsoft.DataFactory.LinkedService.json`"
}"

        $SQLDW | Out-File -FilePath "$JsonTemplatePath\$LinkedServiceFileName" -Encoding ascii -Force
        Start-Sleep -Seconds 5
        $LinkedServerTemplate = $null
        $LinkedServerTemplate = ConvertFrom-Json (Get-Content "$JsonTemplatePath\$LinkedServiceFileName" -Raw)
        New-AzureRmDataFactoryLinkedService -DataFactory $dataFactory -File "$JsonTemplatePath\$LinkedServiceFileName" -Force
        Start-Sleep -Seconds 2
        Remove-Item -Path "$JsonTemplatePath\$LinkedServiceFileName" -Force
}

################################################## Tabs-sFTP ################################################
if((-not($AlreadyExistingLinkedServices | where {$_.LinkedServiceName -eq 'Tabs-sFTP'})) -or ("Tabs-sFTP" -eq $UpdateLinkedService)) {
        Write-Output "Creating linked service: Tabs-sFTP"
        $TodayDate = [string](Get-Date -Format 'yyyy-MM-dd')
        $LinkedServiceFileName = "Tabs-sFTP" + [string](Get-Date -Format ddMMYYmmhhss) + ".json"

        $username = $parameters.parameters.TabsSFTPUserName.value
        $KeyName = $parameters.parameters.TabsSFTPKeyName.value
        $secret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $KeyName -ErrorAction SilentlyContinue
        $SecurePassword = $secret.SecretValue
        $Password = (New-Object PSCredential "$KeyName",$SecurePassword).GetNetworkCredential().Password
        $TabssFTP = $null

$TabssFTP= "{
  `"name`": `"Tabs-sFTP`",
  `"properties`": {
    `"type`": `"Sftp`",
    `"typeProperties`": {
      `"host`": `"52.28.101.76`",
      `"port`": 22,
      `"authenticationType`": `"Basic`",
      `"username`": `"$Username`",
      `"password`": `"$Password`",
      `"privateKeyPath`": `"`",
      `"skipHostKeyValidation`": true,
      `"hostKeyFingerprint`": `"`",
      `"gatewayName`": `"`",
      `"encryptedCredential`": `"`"
    }
  },
  `"`$schema`": `"http://datafactories.schema.management.azure.com/internalschemas/2015-09-01/Microsoft.DataFactory.linkedservice.json`"
}"
        $TabssFTP | Out-File -FilePath "$JsonTemplatePath\$LinkedServiceFileName" -Encoding ascii -Force
        Start-Sleep -Seconds 5
        $LinkedServerTemplate = $null
        $LinkedServerTemplate = ConvertFrom-Json (Get-Content "$JsonTemplatePath\$LinkedServiceFileName" -Raw)
        New-AzureRmDataFactoryLinkedService -DataFactory $dataFactory -File "$JsonTemplatePath\$LinkedServiceFileName" -Force
        Start-Sleep -Seconds 2
        Remove-Item -Path "$JsonTemplatePath\$LinkedServiceFileName" -Force
}

###################################### EnterraStorageLinkedService ##############################
if((-not($AlreadyExistingLinkedServices | where {$_.LinkedServiceName -eq 'EnterraStorageLinkedService'})) -or ("EnterraStorageLinkedService" -eq $UpdateLinkedService)) {
        Write-Output "Creating linked service: EnterraStorageLinkedService"
        $TodayDate = [string](Get-Date -Format 'yyyy-MM-dd')
        $LinkedServiceFileName = "EnterraStorageLinkedService" + [string](Get-Date -Format ddMMYYmmhhss) + ".json"

        $KeyName = $Parameters.parameters.EnterraStorageLinkedServiceKeyName.value
        $AccountName = $Parameters.parameters.EnterraStorageLinkedServiceAccountName.value
        $secret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $KeyName -ErrorAction SilentlyContinue
        $SecurePassword = $secret.SecretValue
        $AccountKey = (New-Object PSCredential "$KeyName",$SecurePassword).GetNetworkCredential().Password
        $EnterraStorage = $null

$EnterraStorage = "{
  `"name`": `"EnterraStorageLinkedService`",
  `"properties`": {
    `"description`": `"`",
    `"type`": `"AzureStorage`",
    `"typeProperties`": {
      `"connectionString`": `"DefaultEndpointsProtocol=https;AccountName=$AccountName;AccountKey=$AccountKey`"
    }
  },
  `"`$schema`": `"http://datafactories.schema.management.azure.com/internalschemas/2015-09-01/Microsoft.DataFactory.linkedservice.json`"
}"

        $EnterraStorage | Out-File -FilePath "$JsonTemplatePath\$LinkedServiceFileName" -Encoding ascii -Force
        Start-Sleep -Seconds 5
        $LinkedServerTemplate = $null
        $LinkedServerTemplate = ConvertFrom-Json (Get-Content "$JsonTemplatePath\$LinkedServiceFileName" -Raw)
        New-AzureRmDataFactoryLinkedService -DataFactory $dataFactory -File "$JsonTemplatePath\$LinkedServiceFileName" -Force
        Start-Sleep -Seconds 2
        Remove-Item -Path "$JsonTemplatePath\$LinkedServiceFileName" -Force
}

###################################### OnPremisesFileServerLinkedService ##############################
if((-not($AlreadyExistingLinkedServices | where {$_.LinkedServiceName -eq 'OnPremisesFileServerLinkedService'})) -or ("OnPremisesFileServerLinkedService" -eq $UpdateLinkedService)) {
        Write-Output "Creating linked service: OnPremisesFileServerLinkedService"
        $TodayDate = [string](Get-Date -Format 'yyyy-MM-dd')
        $LinkedServiceFileName = "OnPremisesFileServerLinkedService" + [string](Get-Date -Format ddMMYYmmhhss) + ".json"
        $KeyName = $parameters.parameters.OnPremiseFileServerKeyName.value
        $UserID = ($parameters.parameters.OnPremiseFileServerUserID.value).Replace("\","\\")
        $secret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $KeyName -ErrorAction SilentlyContinue
        $SecurePassword = $secret.SecretValue
        $Password = (New-Object PSCredential "$KeyName",$SecurePassword).GetNetworkCredential().Password
        $OnPremLinkedService = $null


$OnPremLinkedService = "{
  `"name`": `"OnPremisesFileServerLinkedService`",
  `"properties`": {
    `"description`": `"`",
    `"type`": `"OnPremisesFileServer`",
    `"typeProperties`": {
      `"host`": `"$gatewayhost`",
      `"gatewayName`": `"$GateWayName`",
      `"userId`": `"$UserID`",
      `"password`": `"$Password`"
    }
  },
  `"`$schema`": `"http://datafactories.schema.management.azure.com/internalschemas/2015-09-01/Microsoft.DataFactory.linkedservice.json`"
}"

        $OnPremLinkedService | Out-File -FilePath "$JsonTemplatePath\$LinkedServiceFileName" -Encoding ascii -Force
        Start-Sleep -Seconds 5
        $LinkedServerTemplate = $null
        $LinkedServerTemplate = ConvertFrom-Json (Get-Content "$JsonTemplatePath\$LinkedServiceFileName" -Raw)
        New-AzureRmDataFactoryLinkedService -DataFactory $dataFactory -File "$JsonTemplatePath\$LinkedServiceFileName" -Force
        Start-Sleep -Seconds 2
        Remove-Item -Path "$JsonTemplatePath\$LinkedServiceFileName" -Force
}

    # Code to deploy Data Set  
    foreach ($file in $DataSets)  
    {
        $svc = $null
        $FileName = $null
        $FileName = (Split-Path -Path $file -leaf)
        $svc = ConvertFrom-Json (Get-Content "$file" -Raw)
            Write-Output "Creating dataset: $FileName"
            $Status = New-AzureRmDataFactoryDataset -DataFactory $dataFactory -File "$file" -Force
    }
   
    # Code to deploy Pipeline
    foreach ($file in $Pipelines)  
    {
        $svc = $null
        $FileName = $null
        $FileName = (Split-Path -Path $file -leaf)
        $svc = ConvertFrom-Json (Get-Content "$file" -Raw)
        ############################  ADLS Argument addition #######################################
        $DataLakeID = "adl://" + $adlStoreName + ".azuredatalakestore.net"
        $svc = Get-Content $File -raw | ConvertFrom-JSON
        $NewFileName = "Pipeline" + [string](Get-Date -f 'ddMMyyhhmmss') + ".json"
        $NewFilePath = (Split-Path -Path $File -Parent) + "\$NewFileName"
        ForEach($Section in $svc.properties.activities | where {$_.Type -eq 'HDInsightSpark'}) {
            if($Section.typeProperties.arguments) {
                if($Section.typeProperties.arguments -match ".azuredatalakestore.net") {
                    Write-Output "Modifying ADLStore: $DataLakeID"
                    $PreviousContent = $Section.typeProperties.arguments -match "azuredatalakestore.net"
                    $NewArguments =@()
                    ForEach($Arg in $Section.typeProperties.arguments) {
                        if($Arg -eq $PreviousContent) { $NewArguments += $DataLakeID }
                        else { $NewArguments += $Arg }
                    }
                    $Section.typeProperties.arguments = $NewArguments
                }
                else {
                    Write-Output "Adding ADLStore: $DataLakeID"
                    $Section.typeProperties.arguments = $Section.typeProperties.arguments + $DataLakeID
                }
                $svc | Convertto-JSON -Depth 100 | Out-File -FilePath $NewFilePath -Force -Encoding ascii
                $File = $NewFilePath
            }
        }
        ############################################################################################    
        Write-Output "Creating Pipeline: $FileName"
        $Status = New-AzureRmDataFactoryPipeline -DataFactory $dataFactory -File "$file" -Force
        remove-item -Path $file -ErrorAction SilentlyContinue
    }

    write-output "Checking Ready status for DataSet ClusterAvailabilityTriggerforADF, returns true if set"
    & "$PSScriptRoot\Set-ADFDataSlice.ps1" -parameterFile $parameterFile

    Write-Output "Script execution completed successfully"