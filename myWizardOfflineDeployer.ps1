param ([Parameter(Mandatory = $true)]
    $ConfigFile = '.\myWizard-2022-5.0.0-1000-TrainingDemo.bdef.tmp',

    [Parameter(Mandatory = $true)]
    $MacroJsonFile = '.\myWizard-Installer.macro.tmp',
    [Parameter(Mandatory = $true)]
    $AESKey = '',
    [Parameter(Mandatory = $true)]
    $VectorKey = ''

)

function Get-ResourcesForServer {
    param (
        $ServerTemplateUid,
        [ValidateSet("MongoDbRestore", "Packages", "PythonApps", "Tomcat", "WebSites", "WindowsServices", "DataLoaderConfigurations")]
        $ResourceName,
        $bdef
    )
    begin {
    }
    process {
        $serverTemplate = $bdef.ServerTemplates | Where-Object { $_.ServerTemplateUid -eq $ServerTemplateUid }

        if($serverTemplate | Get-Member | Where-Object {$_.Name -match $ResourceName}) {

            $serverTemplate = $serverTemplate | Select-Object -ExpandProperty $ResourceName
            if ($serverTemplate -ne $null) {
                $uid = $serverTemplate | Get-Member | Where-Object {$_.Name -match "uid"} | Select-Object -ExpandProperty Name
                return $bdef.Resources.$ResourceName | Where-Object {$_.$uid -in $serverTemplate.$uid -and $_.IsDeploymentEnabled -eq $true}
            }
        }
    }
}

function BackupApp {
    param
    (
        $AppPath
    )
  
  $Path = "/var/mywizard-backup"
$Days = "2"
$CurrentDate = (Get-Date -Format yyyyMMdd)
Get-ChildItem $Path  | ForEach-Object { 
            $folderName = $_.Name
            $fullPath = $_.FullName
            $date = $folderName.Split("_")
            $diff = $CurrentDate - $date[1]
            If ($diff -gt $Days) {
                Write-Host "Remove-Item -Path $fullPath -Force -Recurse"
                Remove-Item -Path $fullPath -Force -Recurse
            }
        }

if (Test-Path -Path "$AppPath") {
New-Item -ItemType Directory -Force -Path $Path
if ( -Not ("$AppPath" -like "*GatewayManager*")) {
    $BackupPath = "$AppPath".Replace("www","mywizard-backup") + "_" + (Get-Date -Format yyyyMMdd.hhmmss)
	write-Host $AppPath  $BackupPath 
    Move-Item $AppPath -Destination $BackupPath -Force
}
else {
    $gmFolder = $Path + "/GatewayManager_" + $(Get-Date -Format yyyyMMdd)
    if("$AppPath" -match "bin") {
        New-Item -ItemType Directory -Force -Path $gmFolder"/bin" | Out-Null
        Move-Item $AppPath -Destination $gmFolder"/bin" -Force
    }
    New-Item -ItemType Directory -Force -Path $gmFolder"/ProcessPipelines" | Out-Null
    $AppPathProcessPipeline = "$AppPath".Replace("bin","ProcessPipelines")
    Get-ChildItem $AppPathProcessPipeline -Recurse | Where-Object { $_ -notmatch "ProcessLogs" -and $_ -notmatch "Instances" } | ForEach-Object { Copy-Item -Path $_.FullName -Destination $_.FullName.Replace("var/www/GatewayManager",$gmFolder) }
}
}

}

function lxArchive {
    param
    (
        $Source,
        $Destination
    )
   
Write-Host $("Extracting app from " + $Source + " to" + $Destination)
#Expand-Archive -Path "$Source" -DestinationPath "$Destination" -Force | Add-Content -Path /var/www/zipout.txt
New-Item -ItemType Directory -Path "/var/www/Logs/UnzipLogs/" -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path "$Destination" -Force -ErrorAction SilentlyContinue | Out-Null
$outfile = "$("/var/www/Logs/UnzipLogs/$(Split-Path -Path $Destination -Leaf).txt")"
unzip -o $Source -d $Destination > $outfile

}

function ReplaceMacrosTask {
    param
    (
        $AppNode,
        $MacroJsonFile
    )
	$Password = [System.Web.HttpUtility]::UrlEncode($DBPwd)
    $ReplaceMacrosTasks = $AppNode.ReplaceMacrosTasks
    $Name = $(";appName="+$AppNode.Name)
    $Nameand = $("&appName="+$AppNode.Name)
    $MountPath = $DscEnvironmentSettings.LinuxMountPath
	$AzureAuth = $DscEnvironmentSettings.AuthProvider
    $MacroJsonFile = $($MountPath + '/' + (Split-Path -Path $MacroJsonFile -Leaf))
    
    if($ReplaceMacrosTasks.Count -ge 1)
    {       
$DefaultMacros = Get-Content -Raw  -Path $MacroJsonFile 
$DefaultMacros = /mnt/win/myWizardSource/Scripts/Common/Cryptography.ps1 -Action Decrypt -text $DefaultMacros -KeyValue $AESKey -VectorValue $VectorKey | ConvertFrom-Json
foreach($file in "$ReplaceMacrosTasks".Split(' '))
{
    if(Test-Path -Path $file)
    {
        Write-Host ""
        Write-Host ""
        Write-Host "Replacing macros in : " $file
        $configFile = Get-Content -path $file
        [string[]]$macrosInConfig = (([regex]('{\w+}')).Matches($configFile)) | Select-Object -ExpandProperty Value -Unique
        if ($file.EndsWith(".js")){
            $macrosInConfig = $macrosInConfig | Where-Object { $_ -ne "{clientName}"}
            $macrosInConfig = $macrosInConfig | Where-Object { $_ -ne "{Name}"}
        }
        foreach ($macro in $macrosInConfig) {
            if ($null -ne $DefaultMacros.PSObject.Properties.Item($macro).Value) {
                $value = $DefaultMacros.PSObject.Properties.Item($macro).Value
if(($macro -match "DBQueryConnectionString") -or ($macro -match "DBCommandConnectionString"))
{
                         if(($macro -match "MyWizardTestOptimizerRiskDBPrimaryDBQueryConnectionString") -or ($macro -match "MyWizardPatternMiningForSAPDBPrimaryDBQueryConnectionString"))
						{
							$value = $value
						}
						else{
                     If ($value.Contains("&ssl=true")) {
                        $value =$value + "$Nameand"}
                        else {
                        $value =$value + "$Name"}
                    }
					}
if($macro -match "DBAdminAccountPassword"){
                        $value = "$Password"
                    }
if("$AzureAuth" -eq "AzureAD"){
                       if($macro -match "ForgeRockAuthProvider" -or $macro -match "ADFSAuthProvider"){
                        $value = ""}
                    } 

                     if("$AzureAuth" -eq "ForgeRock"){
                       if($macro -match "AzureAD10AuthProvider" -or $macro -match "ADFSAuthProvider"){
                        $value = ""}
                    }
                    if("$AzureAuth" -eq "ADFS"){
                       if($macro -match "AzureAD10AuthProvider" -or $macro -match "ForgeRockAuthProvider"){
                        $value = ""}
                    } 
$configFile = $configFile.Replace($macro,$value )
Write-Host $("Replacing : $macro ===> $value")
}
        }
        Set-Content $file $configFile
    }
}
   }
}

function ReplaceMacrosTaskInFolders {
 
    param
    (
        $AppPath,
        $MacroJsonFile
    )
    $Password = [System.Web.HttpUtility]::UrlEncode($DBPwd)
    $MountPath = $DscEnvironmentSettings.LinuxMountPath
																				  
																	  
	$AzureAuth = $DscEnvironmentSettings.AuthProvider
    $MacroJsonFile = $($MountPath + '/' + (Split-Path -Path $MacroJsonFile -Leaf))    	   

$ReplaceMacrosTasks = (Get-childitem -Path $AppPath).FullName 
$DefaultMacros = Get-Content -Raw -Path $MacroJsonFile 
$DefaultMacros = /mnt/win/myWizardSource/Scripts/Common/Cryptography.ps1 -Action Decrypt -text $DefaultMacros -KeyValue $AESKey -VectorValue $VectorKey | ConvertFrom-Json
foreach($file in $ReplaceMacrosTasks)
{
    if(Test-Path -Path $file)
    {
        Write-Host "Replacing macros in : " $file
        $configFile = Get-Content -Raw -path $file
        [string[]]$macrosInConfig = (([regex]('{\w+}')).Matches($configFile)) | Select-Object -ExpandProperty Value -Unique
        if ($file.EndsWith(".js")){
            $macrosInConfig = $macrosInConfig | Where-Object { $_ -ne "{clientName}"}
            $macrosInConfig = $macrosInConfig | Where-Object { $_ -ne "{Name}"}
             $macrosInConfig = $macrosInConfig | Where-Object { $_ -ne "{ClientUId}"}
        }
        foreach ($macro in $macrosInConfig) {
            if ($null -ne $DefaultMacros.PSObject.Properties.Item($macro).Value) {
				
				if($macro -match "DBAdminAccountPassword"){
                     $DefaultMacros.PSObject.Properties.Item($macro).Value = "$Password"
                    }
				if("$AzureAuth" -eq "AzureAD"){
                       if($macro -match "ForgeRockAuthProvider" -or $macro -match "ADFSAuthProvider"){
                        $value = ""}
                    } 

                     if("$AzureAuth" -eq "ForgeRock"){
                       if($macro -match "AzureAD10AuthProvider" -or $macro -match "ADFSAuthProvider"){
                        $value = ""}
                    }
                    if("$AzureAuth" -eq "ADFS"){
                       if($macro -match "AzureAD10AuthProvider" -or $macro -match "ForgeRockAuthProvider"){
                        $value = ""}
                    }
                $configFile = $configFile.Replace($macro, $DefaultMacros.PSObject.Properties.Item($macro).Value)
                #Write-Host $("Replacing : $macro ===> $DefaultMacros.PSObject.Properties.Item($macro).Value")
				
                    
            }
        }
        Set-Content $file $configFile
    }
}
  
}						   
							 
  function RestartService {
    param
    (
        $ServiceName
    )
  
systemctl enable $ServiceName
systemctl stop $ServiceName
systemctl start $ServiceName
}

function PostDeploymentScript {
    param
    (
        $AppNode
    )
    [string[]]$PostDeploymentScripts = $AppNode.PostDeploymentScript | Where-Object {$_.ToLower().EndsWith(".sh")}
    $MountPath = $DscEnvironmentSettings.LinuxMountPath
   
    if($PostDeploymentScripts.Count -ge 1)
    {
              
        foreach($script in "$PostDeploymentScripts".Split(' '))
        {
        if(Test-Path -Path $script)
        {
        $scriptParent = (Split-Path $Script -Parent)
        Write-Host 'Executing Post deployment script'
        Write-Host $script
        cd $scriptParent
        sudo chmod -R 777 $scriptParent
        sudo dos2unix $script
        sh $script > out.log 2>&1
        }
        else
        {
        Write-Host 'Below script path is incorrect in bdef or file not found'
        Write-Host $scriptParent
        }
        }
    }
}

function ConfigureServer {
 param(
        [Parameter(Mandatory = $true)]
        [Object] $jsonParams
    )
process{
  write-host $jsonParams.DeploymentBundle.Name
  write-Host "Generating pre deployment report"
  write-host "sh /mnt/win/myWizardSource/Scripts/CustomScripts/GeneratePostDeploymentReport.sh Pre"
  sh /mnt/win/myWizardSource/Scripts/CustomScripts/GeneratePostDeploymentReport.sh Pre  
  

  write-Host "Gone fishing: Start"
  Copy-Item -Path "/mnt/win/myWizardSource/Softwares/GoneFishingFiles/html" -Destination "/usr/share/nginx/" -Recurse -Force
 
  [psobject[]] $WebSites = Get-ResourcesForServer -ServerTemplateUid $server.ServerTemplateUId  -ResourceName WebSites -bdef $bdef
   if($WebSites.Count -gt 0) {
            Write-Host "Deploying websites"   
            DeployWebSites $WebSites         
        }
		
		 [psobject[]] $WindowsServices = Get-ResourcesForServer -ServerTemplateUid $server.ServerTemplateUId -ResourceName WindowsServices -bdef $bdef
        if($WindowsServices.Count -gt 0) {
            Write-Host "Deploying Windows Serices"
            DeployWindowsServices $WindowsServices
            
        }
		
		 [psobject[]] $Tomcat = Get-ResourcesForServer -ServerTemplateUid $server.ServerTemplateUId -ResourceName Tomcat -bdef $bdef
        if($Tomcat.Count -gt 0) {
             Write-Host "Deploying Tomcat Apps"
            DeployTomcat $Tomcat
            }

        [psobject[]] $PythonApps = Get-ResourcesForServer -ServerTemplateUid $server.ServerTemplateUId -ResourceName PythonApps -bdef $bdef
        if($PythonApps.Count -gt 0) {
             Write-Host "Deploying Python Apps"
            DeployPythonApps $PythonApps
        }
   
      [psobject[]] $Packages = Get-ResourcesForServer -ServerTemplateUid $server.ServerTemplateUId -ResourceName Packages -bdef $bdef
        if($Packages.Count -gt 0) {
            Write-Host "Deploying package"
            DeployPackages $Packages
        }

        [psobject[]] $MongoDbRestore = Get-ResourcesForServer -ServerTemplateUid $server.ServerTemplateUId -ResourceName MongoDbRestore -bdef $bdef
        if($null -ne $MongoDbRestore) {
            Write-Host "Deploying DB changes"
            DeployMongoDbRestore $MongoDbRestore
        }

   
  Write-Host "Host Change"
  #dos2unix /mnt/win/myWizardSource/Scripts/CustomScripts/HostChange.sh 
  sh /mnt/win/myWizardSource/Scripts/CustomScripts/HostChange.sh 

  Write-Host "Folder permission change execution"
  #dos2unix /mnt/win/myWizardSource/Scripts/CustomScripts/AddFolderPermissions.sh
  sh /mnt/win/myWizardSource/Scripts/CustomScripts/AddFolderPermissions.sh 

  Write-Host "Post Deployment Script"
  sh /mnt/win/myWizardSource/Scripts/CustomScripts/GeneratePostDeploymentReport.sh Post
         
  Write-Host "Remove Gone fishing file"
  remove-item "/usr/share/nginx/html/phoenix/app_offline.html" -ErrorAction SilentlyContinue
}

}

function DeployWebSites {
    param (
        $Resources
    )

    $sourceAppPackagesPath=$DscEnvironmentSettings.LinuxMountPath+"/"+$DscEnvironmentSettings.ApplicationsFolder
    
    foreach($site in $Resources) {
        Write-Host "Deploying website: " $site.WebSitePath
        $websiteName = $site.WebSiteName
        $WebSitePort = $site.WebSitePort
        $WebSitePath = $site.WebSitePath
        $PackageFile = $site.PackageFile
        $InstalledVersion = $site.InstalledVersion
        $PackageFolderName = $site.PackageFolderName
        $WebsiteNodeName = $site.Name
        $ExecutablePath = $site.ExecutablePath
        $sourceFilePath = "$sourceAppPackagesPath/$PackageFolderName/$InstalledVersion/$PackageFile"
         

        Write-Host "Step 1: Backup"
        BackupApp $WebSitePath
		
	    Write-Host "Step 2: Extract binaries"
        lxArchive $sourceFilePath $WebSitePath

        Write-Host "Step 3: Replace Macros"
        ReplaceMacrosTask $site $MacroJsonFile

        Write-Host "Step 4: Service file creation"
        if (!(Test-Path "/etc/systemd/system/$WebsiteNodeName.service")) {
               $content = "[Unit] 
            Description=metrics .NET Web API Application running on CentOS 7

            [Service]
            WorkingDirectory=$WebSitePath
            ExecStart=/usr/bin/dotnet $ExecutablePath 
            Restart=always
            SyslogIdentifier=$WebSitePath
            User=nginx
            Group=nginx
            Environment=ASPNETCORE_ENVIRONMENT=Dev

            [Install]
            WantedBy=multi-user.target
                                "
               New-Item -path /etc/systemd/system/$WebsiteNodeName.service -type "file" -value $content
            }
			
        Write-Host "Step 5: Enable and Restart Service"
        RestartService $WebsiteNodeName
                
    }

}
	
function DeployWindowsServices {
    param (
        $Resources
    )
    
    $sourceAppPackagesPath=$DscEnvironmentSettings.LinuxMountPath+"/"+$DscEnvironmentSettings.ApplicationsFolder
    $localAppPackagesPath = $DscEnvironmentSettings.LocalAppServicesPath
    
    foreach($service in $Resources) {
        $ServiceName = $service.Name
        $ServiceDescription = $service.Description
        $PackageFile = $service.PackageFile
        $ServicePath = $service.ServicePath.Replace("{ApplicationInstallationFolder}", $DscEnvironmentSettings.ApplicationInstallationFolder).Replace("{SoftwareInstallationFolder}", $DscEnvironmentSettings.SoftwareInstallationFolder) 
        $AppServicesPath = $service.AppServicesPath.Replace("{ApplicationInstallationFolder}", $DscEnvironmentSettings.ApplicationInstallationFolder).Replace("{SoftwareInstallationFolder}", $DscEnvironmentSettings.SoftwareInstallationFolder) 
        $Path = $service.Path.Replace("{ApplicationInstallationFolder}", $DscEnvironmentSettings.ApplicationInstallationFolder).Replace("{SoftwareInstallationFolder}", $DscEnvironmentSettings.SoftwareInstallationFolder)
        $StartupType = $service.StartupType
        $State = $service.State
        $ConfigFilePath = $service.ConfigFilePath.Replace("{ApplicationInstallationFolder}", $DscEnvironmentSettings.ApplicationInstallationFolder).Replace("{SoftwareInstallationFolder}", $DscEnvironmentSettings.SoftwareInstallationFolder)
        $InstalledVersion = $service.InstalledVersion
        $PackageFolderName = $service.PackageFolderName
        $sourceFilePath = "$sourceAppPackagesPath/$PackageFolderName/$InstalledVersion/$PackageFile"
        $processpipelinePath = $AppServicesPath.Replace("bin","ProcessPipelines")

        Write-Host "Deploying " $ServiceName
        
		Write-Host "Step 1: Backup"
        BackupApp $AppServicesPath
		
	    Write-Host "Step 2: Extract binaries"
        lxArchive $sourceFilePath $ServicePath

        Write-Host "Step 3: Replace Macros"
        ReplaceMacrosTask $service $MacroJsonFile

        Write-Host "Step 4: Post Deployment Scrpit execution"
        PostDeploymentScript $service

        Write-Host "Step 5: Service file creation"
        if (!(Test-Path "/etc/systemd/system/$ServiceName.service")) {
               $content = "[Unit] 
            Description=metrics .NET Web API Application running on CentOS 7

            [Service]
            WorkingDirectory=$AppServicesPath
            ExecStart=/usr/bin/dotnet $Path 
            Restart=always
            SyslogIdentifier=$ServicePath
            User=nginx
            Group=nginx
            Environment=ASPNETCORE_ENVIRONMENT=Dev

            [Install]
            WantedBy=multi-user.target
                                "
               New-Item -path /etc/systemd/system/$ServiceName.service -type "file" -value $content
            }
          
		Write-Host "Step 6: Enable and Restart Service"
        RestartService $ServiceName
    }
}

function DeployTomcat {
 param (
        $Resources
    )
    
    $sourceAppPackagesPath=$DscEnvironmentSettings.LinuxMountPath+"/"+$DscEnvironmentSettings.ApplicationsFolder
    $sourceSoftwarePath=$DscEnvironmentSettings.LinuxMountPath+"/Softwares/tomcat9"
    
    Write-Host "Stopping Tomcat Service"
    systemctl stop tomcat
	
    Write-Host "Backup tomcat conf"
	Write-Host "Backup Tomcat server.xml and TomcatCatalinaFile"
    BackupApp "/etc/tomcat9/conf/server.xml"
    BackupApp "/etc/tomcat9/conf/catalina.properties"
	
	Write-Host "Replace latest tomcat conf"
    Copy-Item "$sourceSoftwarePath/server.xml" -Destination "/etc/tomcat9/conf/"
    Copy-Item "$sourceSoftwarePath/catalina.properties" -Destination "/etc/tomcat9/conf/"
   
    $localAppPackagesPath = $DscEnvironmentSettings.LocalAppServicesPath
    foreach($tomcatNode in $Resources)
    {
        $Name = $tomcatNode.Name
        $PropertyFileFullPath = $tomcatNode.PropertyFilePath
        $WarFileFullPath = $tomcatNode.WarFilePath
        $PackageFile = $tomcatNode.PackageFile
        $PackageFolderName = $tomcatNode.PackageFolderName
        $InstalledVersion = $tomcatNode.InstalledVersion

        $PropertyFilePath = (Split-Path -Path $PropertyFileFullPath).Replace('\','/')
        $PropertyFileName = Split-Path -Path $PropertyFileFullPath -Leaf

        $WarFilePath = (Split-Path -Path $WarFileFullPath).Replace('\','/')
        $WarFileName = Split-Path -Path $WarFileFullPath -Leaf
            
        # source filepath
        $sourceTomcatAppPackagesPath = $sourceAppPackagesPath + "/$PackageFolderName/$InstalledVersion/$PackageFile"
        $sourceTomcatAppPropertyFilePath = $sourceAppPackagesPath + "/$PackageFolderName/$InstalledVersion/$PropertyFileName"
		
		Write-Host "Deploying "$Name 
		
        Write-Host "Step 1: Backup" 
		BackupApp $WarFileFullPath
		BackupApp $PropertyFileFullPath

        if("$Name" -match "IntelligentReleasePlanner.WebAPI") {
            Remove-Item -Path "/etc/tomcat9/webapps/IntelligentReleasePlanner" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if("$Name" -match "RequirementsReadinessAnalyzer.WebAPI") {
            Remove-Item -Path "/etc/tomcat9/webapps/RequirementReadinessAssistant" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Host "Step 2: Extract binaries"
		lxArchive $sourceTomcatAppPackagesPath "/var/www/temp/tomcat/"
         New-Item -ItemType Directory -Force -Path $PropertyFilePath
	Copy-Item "/var/www/temp/tomcat/application.properties"  -Destination  "$PropertyFilePath"
        Copy-Item "/var/www/temp/tomcat/app.json"  -Destination  "$PropertyFilePath"  -ErrorAction SilentlyContinue
        Copy-Item "/var/www/temp/tomcat/application-common-cryptography.jar"  -Destination  "$PropertyFilePath"  -ErrorAction SilentlyContinue
        Copy-Item "/var/www/temp/tomcat/PackageInfo*" -Destination /etc/tomcat9/webapps/  -ErrorAction SilentlyContinue

        Copy-Item "/var/www/temp/tomcat/$WarFileName" -Destination /etc/tomcat9/webapps/
	Remove-Item "/var/www/temp/tomcat" -Recurse -Force -ErrorAction SilentlyContinue -Confirm:$false
        
        Write-Host "Step 3: Replace Macros"
        ReplaceMacrosTask $tomcatNode $MacroJsonFile

        Write-Host "Step 4: Post Deployment Scripts"
        PostDeploymentScript $tomcatNode
    }
	
     Write-Host "Restart RabbitMq and tomcat service"
	 systemctl restart rabbitmq-server
     systemctl restart tomcat
	
	}

function DeployPythonApps {
 param (
        $Resources
    )

  $sourceAppPackagesPath=$DscEnvironmentSettings.LinuxMountPath+"/"+$DscEnvironmentSettings.ApplicationsFolder
  $sourceSoftwarePath=$DscEnvironmentSettings.LinuxMountPath+"/Softwares/pythonservicefiles"

   foreach($site in $Resources) {
    $websiteName = $site.WebSiteName
    $Path = $site.Path
    $PackageFile = $site.PackageFile
    $InstalledVersion = $site.InstalledVersion
    $PackageFolderName = $site.PackageFolderName
    $WebsiteNodeName = $site.Name
    $sourceFilePath = "$sourceAppPackagesPath/$PackageFolderName/$InstalledVersion/$PackageFile"

    Write-Host "Deploying " $WebsiteNodeName

    Write-Host "Step 1: Backup"
    BackupApp $Path
    
    Write-Host "Step 2: Extract binaries"
    lxArchive $sourceFilePath $Path

    Write-Host "Step 3: Copy Service file"
     if (!(Test-Path "/etc/systemd/system/$WebsiteNodeName.service")) {
        Copy-Item "$sourceSoftwarePath/$WebsiteNodeName.service" -Destination "/etc/systemd/system/"
     }

    Write-Host "Step 4: Replace Macros"
    ReplaceMacrosTask $site $MacroJsonFile

    Write-Host "Step 5: Execute Post Deployment Scripts"
    PostDeploymentScript $site

    Write-Host "Step 6: Enable and Restart Service"
    RestartService $WebsiteNodeName

    }

    
}

function DeployPackages {
 param (
        $Resources
    )

  $sourceAppPackagesPath=$DscEnvironmentSettings.LinuxMountPath+"/"+$DscEnvironmentSettings.ApplicationsFolder

   foreach($package in $Resources) {
    $PackageName = $package.Name
    $PackageDescription = $package.Description
    $PackageFile = $package.PackageFile
    $PackagePath = $package.PackagePath
    $InstalledVersion = $package.InstalledVersion
    $PackageFolderName = $package.PackageFolderName

    $localFilePath = "$sourceAppPackagesPath/$PackageFolderName/$InstalledVersion/$PackageFile"
    Write-Host "Deploying " $PackageName
        
    Write-Host "Step 1: Backup"        
    #backup only GM packages, Others won't be backup
    if ($PackageFile -match "GatewayManager" -and $package.ReplaceMacrosTasks.Count -gt 0) {
        $AppServicesPath = $(Split-Path -Path $package.ReplaceMacrosTasks[0] -Parent).Replace("\\", "/").Replace("\", "/")
        BackupApp $AppServicesPath
    }
    if ($PackageFile -eq "myWizard.Scripts.zip" ) {
        $PackagePath = $PackagePath + "/IncrementalScripts/"
    }

    Write-Host "Step 2: Extract Binaries"
    lxArchive $localFilePath  $PackagePath

    Write-Host "Step 3: Replace Macros"
	ReplaceMacrosTask $package $MacroJsonFile

    Write-Host "Step 4: Run Post Deployment Scripts"
    PostDeploymentScript $package
    
  }
}

function DeployMongoDbRestore {
 param (
        $Resources
    )

   $sourceAppPackagesPath=$DscEnvironmentSettings.LinuxMountPath+"/"+$DscEnvironmentSettings.ApplicationsFolder
   $Password = $DBPwd
write-host "$sourceAppPackagesPath"
    foreach ($node in $Resources)
    {
        $BackupName = $node.BackupName
        $BackupPath = $node.BackupPath
        $DatabaseName = $node.DatabaseName
        $IP = $node.IP
        $Port = $node.Port
        $Name = $node.Name
                
        $InstalledVersion = $node.InstalledVersion
        $PackageFolderName = $node.PackageFolderName
        $ConnectionString = $node.ConnectionString    
    write-host "$PackageFolderName"
    write-host "$InstalledVersion"
write-host "$BackupName"
        $sourceBackUpPackagesPath = "$sourceAppPackagesPath/$PackageFolderName/$InstalledVersion/$BackupName"
                
        $IsSSL = ($ConnectionString -match 'ssl=true')
        $MongoDBServerFolder = $node.MongoDBServerFolder
        $SSLCommand = '--ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem'
        $DatabaseNameUser = $DatabaseName + 'User'
        $BackupPathScript = $BackupPath + "/IncrementalScripts/"
		if($DatabaseName -eq "mywizard-phoenix"){
                $BackupPathScript = $BackupPath
                }
				$BackupPathScriptInc = $BackupPath + "/IncrementalScripts/"
                
        $HostName = $IP


        If ($IP.Contains(",")) {
            $IP = "myWizardMongo1RS/" + $IP 
        }
        If ($node.IsIncremental -eq $true) {
             Remove-Item -Path $BackupPathScript -Recurse -Force | Out-null -ErrorAction SilentlyContinue
             If((Test-Path ($sourceBackUpPackagesPath)) -eq $true) {

                Write-Host "Extracting the Scripts package to a incremental folder"
                lxArchive $sourceBackUpPackagesPath $BackupPathScript
                Write-Host "Replacing macros in folders"
                ReplaceMacrosTaskInFolders $BackupPathScriptInc $MacroJsonFile
           
                 Write-Host "Replacing macros"
                ReplaceMacrosTask $node $MacroJsonFile

                If ($IsSSL -eq $true) {
					If ($DatabaseName -eq "mywizard-phoenix") {
                        $LinuxMountPath = $DscEnvironmentSettings.LinuxMountPath
                        $sourceScriptsPath = "$LinuxMountPath/Scripts/CustomScripts/"
                        
Write-Host "Mongo DB uptodate" 
                        
#!/bin/pwsh
cd $BackupPath/Release
Write-Host "Running Incremental Mongo DataLoader..."
/usr/bin/dotnet Accenture.Mywizard.MongoDataLoader.dll DeployINCJSON DeployINCScripts
                    }
					
					Else{
					
                    $CurrentDate = (Get-Date -Format yyyyMMdd.hhmmss)
                    $LogIncrementalPath = "/var/www/Logs/IncrementalScripts/$DatabaseName.$CurrentDate.log"
                    $DBHost = "$HostName"

                    Start-Transcript -Path $LogIncrementalPath
                    Write-Host

                    If ("$DatabaseName" -ne "mywizard-phoenix"){
                    Write-Host "Taking DB backup - $DatabaseName" 
                    #mongodump --host $IP --db $DatabaseName --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem --authenticationDatabase $DatabaseName -u $DatabaseNameUser -p 'myWizard@123' --out /var/IncrementalBackup
mongodump --host $IP --db $DatabaseName --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem --authenticationDatabase $DatabaseName -u $DatabaseNameUser -p $Password --out /var/IncrementalBackup                    
Write-Host
                    }

                    If ($DBHost.Contains(",")) {
                        $result = Invoke-Expression -Command "mongo $DBHost/$DatabaseName -u admin -p $Password --authenticationDatabase admin --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem --quiet --eval 'rs.status().members.find(r=>r.state===1).name'"
                        $DBHost = $result[$result.Length - 1]
                         Write-Host "DatabasePrimaryHostName : $DBHost and Command used for finding primary host as follows"
                         Write-Host "mongosh $DBHost/$DatabaseName -u admin -p $Password --authenticationDatabase admin --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem --quiet --eval 'rs.status().members.find(r=>r.state===1).name'"
                    }

                    $files  = Get-ChildItem $BackupPathScript
                    foreach ($file in $files) {
                        Write-Host
                        Write-Host "Executing Incremental Scripts for DB - $DatabaseName, ScriptName - $file" 
                        mongosh $DBHost/$DatabaseName -u $DatabaseNameUser -p $Password --authenticationDatabase $DatabaseName  --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem  $file
                        Write-Host "Script execution completed"
                        Write-Host
                    }
                    Stop-Transcript

                    Copy-Item -Path "$LogIncrementalPath" -Destination "/mnt/win/myWizardSource/Logs" -Recurse -Force -ErrorAction SilentlyContinue

                }
				}
			 
                Else {
                    mongosh -host $IP -u admin -p $Password --eval "db.getSiblingDB('$DatabaseName').createUser({user:'$DatabaseNameUser','pwd': '$Password', roles : [{role: 'readWrite', db:'$DatabaseName'},{role: 'dbAdmin', db:'$DatabaseName'}]})"
                    $files  = Get-ChildItem $BackupPathScript
                    foreach ($file in $files) {
                    mongosh $IP/$DatabaseName -u admin -p $Password --authenticationDatabase admin$file
                }
             }
           
            }
        }
		
        Else {
            Write-Host "Extract the application package to a folder"
            lxArchive $sourceBackUpPackagesPath $BackupPath

            ReplaceMacrosTask $node $MacroJsonFile

             If ($IsSSL -eq $true) {
                 If ($DatabaseName -eq "mywizard-phoenix") {
                        $LinuxMountPath = $DscEnvironmentSettings.LinuxMountPath
                        $sourceScriptsPath = "$LinuxMountPath/Scripts/CustomScripts/"
                        $ProductInstanceScriptPath = $sourceScriptsPath + "FillProductInstanceByProductVersion.js"
                        $ProductInstanceDeserializationPath = $sourceScriptsPath + "ProductInstanceDeserializationFixes.js"
                        $EntityUIdScriptPath = $sourceScriptsPath + "MetricMeasure_EntityUId_WorkItemTypeUId_update.js"
                        New-Item -Path $BackupPath/ObjectJSON -ItemType 'Directory' -Force
                        $customDataPath = "$($DscEnvironmentSettings.LinuxMountPath + "/AppServices/myWizard/$InstalledVersion/*")"
                        Copy-Item $customDataPath -Destination $BackupPath/ObjectJSON -Force -Recurse
                        cd $BackupPath/Release
						Write-Host "Running Mongo DataLoader For Fresh DataBase..."
                        /usr/bin/dotnet Accenture.Mywizard.MongoDataLoader.dll DeployDB
						Write-Host "Running Encryption..."
						cd $BackupPath/MyWizard.DB.Encryption
						/usr/bin/dotnet Accenture.Mongo.DataEncryption.dll
						Write-Host "Running Creating DB USERS..."
						mongosh -host $IP -u admin -p $Password --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem --eval "db.getSiblingDB('$DatabaseName').createUser({user:'$DatabaseNameUser','pwd': '$Password', roles : [{role: 'readWrite', db:'$DatabaseName'},{role: 'dbAdmin', db:'$DatabaseName'}]})"
						Write-Host "Running FillProductInstanceByProductVersion Script..."
						mongosh $IP/$DatabaseName -u admin -p $Password --authenticationDatabase admin --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem $ProductInstanceScriptPath > /var/www/Mongo.DataLoader/FillProductInstanceByProductVersion.log
						Write-Host "Running ProductInstanceDeserializationFixes Script..."
						mongosh $IP/$DatabaseName -u admin -p $Password --authenticationDatabase admin --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem $ProductInstanceDeserializationPath > /var/www/Mongo.DataLoader/ProductInstanceDeserializationFixes.log
						Write-Host "Running MetricMeasure_EntityUId_WorkItemTypeUId_update Script..."
						mongosh $IP/$DatabaseName -u admin -p $Password --authenticationDatabase admin --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem $EntityUIdScriptPath > /var/www/Mongo.DataLoader/MetricMeasureEntityUIdWorkItemTypeUIdupdate.log
                        
                 }
                 Else {
                    mongorestore --host $IP --db $DatabaseName $BackupPath -u admin -p $Password --authenticationDatabase admin --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem --quiet --drop
                    mongosh -host $IP -u admin -p $Password --ssl --sslCAFile /mongo/certificates/CA.crt --sslPEMKeyFile /mongo/certificates/server.pem --eval "db.getSiblingDB('$DatabaseName').createUser({user:'$DatabaseNameUser','pwd': '$Password', roles : [{role: 'readWrite', db:'$DatabaseName'},{role: 'dbAdmin', db:'$DatabaseName'}]})"
                 }
             }
             Else{
                mongorestore --host $IP --db $DatabaseName $BackupPath --drop -u admin -p $Password --authenticationDatabase admin --quiet --drop
                mongosh -host $IP -u admin -p $Password --eval "db.getSiblingDB('$DatabaseName').createUser({user:'$DatabaseNameUser','pwd': '$Password', roles : [{role: 'readWrite', db:'$DatabaseName'},{role: 'dbAdmin', db:'$DatabaseName'}]})"
             }
			 

            PostDeploymentScript $node
        }
    }
}
function MoveLogs {

    
    Copy-Item -Path "/mnt/win/myWizardSource/Scripts/CustomScripts/HTML/*" -Destination ".\" -Force
    (Get-ChildItem -Path "/mnt/win/myWizardSource/Logs/Reports" -File | Where-Object {$_.FullName -match 192.168.16.83}).FullName | Move-Item -Destination ".\Reports\" -Force


    $arr = Get-ChildItem ".\Reports"| Select Name | Sort-Object Name -Descending
    $fs = "  <li class=`"nav-item`">
                       <a class=`"nav-link`" href=`"#`" >filename</a>
                    </li>"
    $fs1 = "`n"
    foreach ($item in $arr)
    {
      #if (($item.Name -ne "menu.html") -AND  ($item.Name -ne "Header.html"))
      #{
        $fs1=$fs1 + $fs -replace "filename", $item.Name
        $fs1 = $fs1 +  "`n"
      #}
    }

    $fs1 = " <ul id=`"menu`" class=`"nav flex-column`" style=`"font-family: inherit;`">   " + $fs1
    #Write-Host $fs1
    (Get-Content ".\ReportIndex.html") -replace '<ul id="menu" class="nav flex-column" style="font-family: inherit;"> ', $fs1 | Set-Content ".\ReportIndex.html"
}

function Send-Email {
    begin {
        [securestring]$password = ConvertTo-SecureString 'BDPcatF9k7BrUac8OfW0vzq2YYPfEs1AnbujyqA20VOP' -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential ('AKIASLNFXDCIMFECR5PM', $password)
        $from = "OneClick Installer <oneclick@mywizard360.com>"
        $smtp = "email-smtp.us-east-1.amazonaws.com"
        $port = 587
        $ClientName = $ReleaseVersion + "_" + $DeploymentEnvironment
    }
    process {

        [string[]]$to = @(
                            "p.kumar.estamsetti@accenture.com",
                            "anurag.a.mohapatra@accenture.com",
                            "anshuman.saini@accenture.com",
                            "gowthami.chirugudi@accenture.com",
                            "shekhar.c.singh@accenture.com",
                            "jahnavi.a.r@accenture.com",
                            "vikram.s.gopal@accenture.com",
                            "aishwarya.j.hegde@accenture.com",
                            "m.c.kumar.srivastava@accenture.com",
                            "rajendra.p.mandla@accenture.com",
                            "jami.meghana@accenture.com",
                            "a.narasimharaju@accenture.com",
                            "akanksha.k.pandey@accenture.com",
                            "shaon.roy@accenture.com",
                            "k.keerthi.krishna@accenture.com",
                            "niharika.q.singh@accenture.com",
                            "nerala.vani@accenture.com",
                            "vikram.b.krishnan@accenture.com",
                            "praveenkumar.rj@accenture.com"
                        )
        $installerVersion = "{AdminConsoleVersionNumber}"
        $subject = $("OCI - Deployment completion alert " + $ClientName +" at the server: " + $ip)
        $body = $("<!DOCTYPE html> <html lang='en'> <head> <meta charset='UTF-8'> <meta name='viewport' content='width=device-width, initial-scale=1.0'> <title>Document</title> <style> html,head,body,div,span { margin: 0; padding: 0; font-family: 'Calibri (Body)'; font-size: 12pt; } .logitems { padding: 0 0 0 20px; } .adminConsole { color: gray; font-size: 10pt; } </style> </head> <body>Hi Team,<br><br> Attaching the zip with the following : <br> <span class='logitems'> - Deploy logs</span><br> <span class='logitems'> - Build logs</span><br> <span class='logitems'> - Dsc logs</span><br> <span class='logitems'> - Omiserver logs</span><br> <span class='logitems'> - Post deployment reports</span><br><br> Deployment completed from <b>" + $localPath + "</b> folder.<br><br><br> Thanks,<br> myWizard - OneClickInstaller,<br>" + $env:USERNAME + "<br><br> <span class='adminConsole'>NOTE: This deployment is completed using OneClickInstaller - " + $installerVersion + "</span> </body> </html>")
        Get-ChildItem -Path ".\*" | Compress-Archive -DestinationPath $(".\" + $ClientName + "_" + $ip + ".zip") -Force -CompressionLevel Optimal

       
        [string[]]$attachments = @($(".\" + $ClientName + "_" + $ip + ".zip"))

        if ($null -ne $attachments) {
            Send-MailMessage -From $from -To $to -Subject $subject -Body $body -BodyAsHtml -UseSsl -Credential $cred -SmtpServer $smtp -Port $port -Attachments $attachments
        }
        else {
            Send-MailMessage -From $from -To $to -Subject $subject -Body $body -BodyAsHtml -UseSsl -Credential $cred -SmtpServer $smtp -Port $port
        }
    }
}


Write-Host "Clean up the logs"
#$ip=$(/sbin/ip -o -4 addr list eth0) | ForEach-Object{($_ -split "\s+")[3]} 
#$ip=$ip.Substring(0,$IP.IndexOf("/"))
$ip=$(hostname -I|cut -d" " -f 1)
rm -rf /mnt/win/myWizardSource/Logs/Log_$ip/*
mkdir -p /mnt/win/myWizardSource/Logs/Log_$ip/Reports
mkdir -p /var/www/tempLogs/

Start-Transcript -Path "/var/www/tempLogs/ReportsDeploymentTranscript-$ip-$(Get-Date -Format "ddMMyyyy").log"


$MacroJsonFile = "myWizard-Installer.macro.tmp"

$encryptedBdef = Get-Content -Raw -Path $ConfigFile
$bdef = /mnt/win/myWizardSource/Scripts/Common/Cryptography.ps1 -Action Decrypt -KeyValue $AESKey -VectorValue $VectorKey -text $encryptedBdef | ConvertFrom-Json

#$bdef = Get-Content  -Path $ConfigFile | ConvertFrom-Json
$DscEnvironmentSettings = $bdef.Environment

$jsonParams = $bdef
Set-Content -Value $jsonParams -Path ./test.json
$server = $jsonParams.Servers | Where-Object { $_.Name -eq $ip } | Select-Object
$DeploymentEnvironment = $jsonParams.Environment.DeploymentEnvironment
$ReleaseVersion = $jsonParams.ReleaseVersion
$DBPwd =$jsonParams.Environment.DBAdminPassword

ConfigureServer $jsonParams
Stop-Transcript
mv /var/www/tempLogs/* /mnt/win/myWizardSource/Logs/Log_$ip/Reports
cd /mnt/win/myWizardSource/Logs/Log_$ip/
MoveLogs
Send-Email
