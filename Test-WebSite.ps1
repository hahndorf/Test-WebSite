<#
.SYNOPSIS
    Script to test an IIS website for the most common setup problems.
.DESCRIPTION
    The script tries to tests a single IIS web site and will make suggestions on how
    to fix potential problems.
.PARAMETER Name
    The name of the web site to test, as seen in IIS Manager or 'Get-WebSite'
.PARAMETER Resource
    the url part of the resource to test starting with the with slash after the hostname/port
    on the full url. Always start with a forward slash. If empty, the home page of the site will
    be tested.
.PARAMETER mvc
    To indicate that the resource to be checked is expected to be handled by ASP.NET MVC
.PARAMETER install
    Installs required IIS components.
.PARAMETER SkipPrerequisitesChecks
    If specified, several checks for prerequisites are not performed. Because these cecks may take
    some time you can choose to skip them if you are sure you have them.
.PARAMETER DontOfferFixes
    If specified, the user will never be asked to run fixes. Useful for testing
.EXAMPLE       
    Test-WebSite -Name MySite
    Uses the default tests against the web site named 'MySite'
.EXAMPLE       
    Test-WebSite -Resource "/login.asp?user=foo" -SkipPrerequisitesChecks
    Uses the default tests against the specified resource on the web site named 'Default Web Site'. Skips checks.
.NOTES

    The exit values are integer number between 10000 and 10000
    They are calculated by multiplying the http status times 100 and add the substatus
    So an normal okay is 20000
    a 404.8 is 40408
    a 500.19 is 50019

    Author: Peter Hahndorf
    Date:   July 1, 2015    
#>

[CmdletBinding()]
[OutputType([int])]
param(
 [Parameter(Position=0)]
  [string]$Name = "Default Web Site",
  [ValidatePattern("/[-\?/\.=&a-z0-9]*")]
  [string]$Resource = "",
  [switch]$install,
  [alias("skip")]
  [switch]$SkipPrerequisitesChecks,
  [switch]$mvc,
  [switch]$DontOfferFixes,
  [switch]$EnableFreb,
  [switch]$DisableFreb
)

    Begin
    {
        $UserCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userIsAdmin = $false
        $UserCurrent.Groups | ForEach-Object { if($_.value -eq "S-1-5-32-544") {$userIsAdmin = $true} }

        $statusInfo = New-Object 'System.Collections.Generic.dictionary[string,string]'
        $statusInfo.Add("404.0","The file that you are trying to access does not exist")
        $statusInfo.Add("404.3","The current MIME mapping for the requested extension type is not valid or is not configured.")
        $statusInfo.Add("401.3","This HTTP status code indicates a problem in the NTFS file system permissions. This problem may occur even if the permissions are correct for the file that you are trying to access. For example, this problem occurs if the IUSR account does not have access to the C:\Winnt\System32\Inetsrv directory. For more information about how to resolve this problem, check the article in the Microsoft Knowledge Base: 942042 ")
        $statusInfo.Add("500.19","The related configuration data for the page is invalid or can not be accessed.")

        Function Get-ExitCode([int]$status,[int]$sub)
        {
            return ($status * 100) + $sub
        }

        Function Show-PoshCommand([string]$info,[string]$intro)
        {
            $info | clip
            if ($intro -ne $null)
            {
                Write-Host $intro 
            }
            else
            {
                Write-Host "You may use the following command:"
            }
            Write-Host $info -ForegroundColor Black -BackgroundColor Gray
            Write-Host "This command has been copied to your clipboard"
        }

        Function Install-IISFeature([string]$name)
        {
            if ((Get-WindowsOptionalFeature –Online | Where {$_.FeatureName -eq $name -and $_.State -eq "Enabled"}).count -eq 0) 
            {
                Write-Output "Running: Enable-WindowsOptionalFeature -Online -FeatureName $name "
                Enable-WindowsOptionalFeature -Online -FeatureName $name           
            }
            else
            {
                Write-Output "$name is already installed"
            }
        }

        Function Install-IISFeatures()
        {
            Install-IISFeature -name IIS-ManagementScriptingTools
            Install-IISFeature -name IIS-HttpLogging 
            Install-IISFeature -name IIS-HttpTracing 
        }

        Function Confirm-Command([string]$message)
        {
            if ($DontOfferFixes)
            {
                return 1
            }
                      
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
               "Executes command now."

            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                "Does not execute the command"

            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            return $host.ui.PromptForChoice("", $message, $options, 1) 

        }

        Function Enable-Tracing
        {
            param(
            [int]$siteId,
            [string]$siteName,
            [string]$statusCodes,
            [string]$resource
            )

            Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@id=$siteId]/traceFailedRequestsLogging" -name "enabled" -value "True"

            Write-Output "Enabling failed request tracing for $resource requests with $statusCodes status..."

            $psPath = "MACHINE/WEBROOT/APPHOST/$siteName"
            $filter = "system.webServer/tracing/traceFailedRequests"

            $pathFilter = "@path='" + $resource + "'"

            # clear any existing stuff
            Remove-WebConfigurationProperty  -pspath $psPath  -filter "system.webServer/tracing/traceFailedRequests" -name "."

            Add-WebConfigurationProperty -pspath $psPath -filter "$filter" -name "." -value @{path=$resource}
            Add-WebConfigurationProperty -pspath $psPath -filter "$filter/add[$pathFilter]/traceAreas" -name "." -value @{provider='ASP';verbosity='Verbose'}
            Add-WebConfigurationProperty -pspath $psPath -filter "$filter/add[$pathFilter]/traceAreas" -name "." -value @{provider='ASPNET';areas='Infrastructure,Module,Page,AppServices';verbosity='Verbose'}
            Add-WebConfigurationProperty -pspath $psPath -filter "$filter/add[$pathFilter]/traceAreas" -name "." -value @{provider='ISAPI Extension';verbosity='Verbose'}
            Add-WebConfigurationProperty -pspath $psPath -filter "$filter/add[$pathFilter]/traceAreas" -name "." -value @{provider='WWW Server';areas='Authentication,Security,Filter,StaticFile,CGI,Compression,Cache,RequestNotifications,Module,FastCGI,WebSocket,Rewrite';verbosity='Verbose'}
            Set-WebConfigurationProperty -pspath $psPath -filter "$filter/add[$pathFilter]/failureDefinitions" -name "statusCodes" -value "$statusCodes"
                       
        }

        Function Disable-Tracing
        {
            param(
                [int]$siteId,
                [string]$siteName
            )

            Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@id=$siteId]/traceFailedRequestsLogging" -name "enabled" -value "False"

            Write-Output "Disabling failed request tracing for this site"

            $psPath = "MACHINE/WEBROOT/APPHOST/$siteName"

            # clear any existing stuff
            Remove-WebConfigurationProperty -pspath $psPath  -filter "system.webServer/tracing/traceFailedRequests" -name "."
                       
        }

        if ($install)
        {
            Install-IISFeatures
            exit 0          
        }

        if (!($SkipPrerequisitesChecks))
        {
            
            Write-Output "Checking prerequisites..."

            if (!($userIsAdmin))
            {
                Write-Warning "Please run this script as elevated administrator"
                Show-PoshCommand "Start-Process -Verb runas -FilePath $PSHOME\powershell.exe"
                Exit 401 # Access denied.
            }

            $componentsMissing = $false

            if(!(Get-Module -ListAvailable -Name WebAdministration))
            { 
                Write-Output "WebAdministration module is missing."
                $componentsMissing = $true
            }


            # checking Get-WindowsOptionalFeature is very slow, so get the features once.

            $iisFeatures = Get-WindowsOptionalFeature –Online | Where {$_.FeatureName -match "^IIS" -and $_.State -eq "Enabled"}

            if (($iisFeatures | Where FeatureName -eq IIS-HttpLogging).count -eq 0) 
            {
                Write-Output "HttpLogging module is missing" 
                $cponentsMissing = $true          
            }

            if (($iisFeatures | Where FeatureName -eq IIS-HttpTracing).count -eq 0)
            {
                Write-Output "Failed Request tracing module is missing" 
                $componentsMissing = $true                        
            }

            if ($componentsMissing)
            {
                Show-PoshCommand "Test-WebSite -install" "One or more modules are missing, please run:"

                $result = Confirm-Command -message "Install required modules now?"

                switch ($result)
                {
                    0 {Install-IISFeatures}
                    1 {}
                }   
            
                Exit 412 # Precondition failed    
            }      
        }
        

        $userAgentRoot = "Test-WebSite"

        Import-Module WebAdministration -Verbose:$false
        
        Function Show-TestSuccess([string]$info)
        {
            Write-Host "Test: $info " -ForegroundColor Green 
        }          

        Function Get-UniqueUserAgent([int64]$ticks)
        {
            Return $userAgentRoot + "_" + $ticks.ToString()
        }

        Function Test-WebPage([string]$url,[int64]$ticks)        
        {
            Write-verbose "Testing: $url"
            $userAgent = Get-UniqueUserAgent -ticks $ticks

            try {
              $res = Invoke-WebRequest -Uri $url -UserAgent $userAgent -Method Get
            
                if ($res.StatusCode -gt  499)
                {
                    $res
                }

                return $res.StatusCode            
            
            } catch {
                Write-Verbose $_.Exception
                return 555
            }
        }

        Function Convert-Binding($binding)
        {

                $url = $binding.protocol + "://"

                $bindingInfo = $binding.BindingInformation.Split(":")

                if ($bindingInfo[0] -eq "*")
                {
                    $url += "127.0.0.1"
                }
                else
                {
                    $url += $bindingInfo[0]
                }
                
                if ($bindingInfo[2] -ne "")
                {
                    $url = $binding.protocol + "://" + $bindingInfo[2]
                }

                if ($bindingInfo[1] -notmatch "80|443")
                {
                    $url += ":" + $bindingInfo[1]
                }

            return $url

        }
       
        Function Process-Problem
        {
            [OutputType([int])]
            param(
            [string]$webRoot,
            [string]$url,
            [int]$status,
            [int]$subStatus,
            [int]$win32Status,
            $pool,
            $site
            )
        
            $fullStatus = "$status.$subStatus"
            Write-Warning "$url - $fullStatus - Win32: $win32Status"

            if ($statusInfo.ContainsKey($fullStatus))
            {
                Write-Warning $statusInfo[$fullStatus]
            }
            else
            {
           #     Write-Warning "This problem is currently not handled"
            }

            # use content from files in C:\inetpub\custerr\en-US
            # to display some information about the problem
            

            $res = $url -replace "^https?://[^/]+", ""
            $res = $res -replace "/","\"
            $potentialResource = Join-Path $webRoot $res

            $AppProcessmodel = ($pool | Select -ExpandProperty processmodel)
            $webRoot = [System.Environment]::ExpandEnvironmentVariables($site.PhysicalPath)

            try
            {
                $defaultDocs = Get-WebConfiguration "system.webserver/defaultdocument/files/*" "IIS:\sites\$($site.Name)" | Select value    
            }
            catch
            {
                Write-Warning "A problem occurred reading the configuration"
            }
            
            If (($res.EndsWith("\")) -or ($res -eq ""))
            {
                # we need to find the default document for this request
                # we could have different default documents in subfolders
                # for now we just check the default documents for the site

                $defaultDocs | ForEach {

                    $file = (Join-Path $webRoot $res)
                    $file = (Join-Path $file $_.value)

                  #  $file

                    if (Test-path $file)
                    {
                        $potentialResource = $file
                    }                   
                }
            }

            Write-Output ""

            # display content from the IIS error pages
            # there may be more than one language we just pick the random first one
            $errorPageDir = Get-ChildItem $env:SystemDrive\inetpub\custerr\ | select -First 1
            # get the full file name for the error page
            $errorPageFile = $status.ToString() + "-" + $subStatus.ToString() + ".htm"
            $errorPageFile = Join-Path $errorPageDir.FullName $errorPageFile

            if (Test-Path $errorPageFile)
            {
                Write-Output "----------------------------------------------------------------------"
                Write-Output "Additional Information:"
                [xml]$errorPage = Get-Content $errorPageFile
                Write-Output $errorPage.html.body.div.div.fieldset.h2
                Write-Output $errorPage.html.body.div.div.fieldset.h3
                Write-Output "----------------------------------------------------------------------"
            }

            Write-Output "Suggested solution:"

            if ($fullStatus -eq "404.0")
            {
                Write-Output "The file `'$potentialResource`' does not exists on disk, please double check the location."
            }
            elseif ($fullStatus -eq "403.14")
            {
                Write-Output "Make sure one of the defined default documents is present in the folder:"
                $defaultDocs | ForEach {
                    Write-Output " - $($_.value) "
                }
                Write-Output "We do not recommend to enable directory browsing"
            }            
            elseif ($fullStatus -eq "404.3")
            {
                If (Test-Path $potentialResource)
                {
                    $extension = [System.IO.Path]::GetExtension($potentialResource)

                    Write-Output "The file $potentialResource exists, but IIS is not configured to serve files with the extension `'$extension`'"
                    Show-PoshCommand "Add-WebConfigurationProperty -pspath `'MACHINE/WEBROOT/APPHOST/$($site.Name)`' -filter 'system.webServer/staticContent' -name '.' -value @{fileExtension=`'$extension`';mimeType='text/html'}" `
                    -intro "Add a new MIME type, but make sure your are using the correct type for this file"
                }
            }
            elseif ($fullStatus -eq "500.19")
            {             
                if ($win32Status -eq 5)
                {
                    Write-Output "Set permissions on web.config"
                } 
                elseif ($win32Status -eq 50)
                {
                    Write-Output "Configuration "
                }  
            }
            elseif ($fullStatus -eq "401.3")
            {
                If (Test-Path $potentialResource)
                {
                    Write-Output "Here are the permissions for file: $potentialResource"
                    (Get-ACL $potentialResource).Access | Select IdentityReference, FileSystemRights, AccessControlType, IsInherited
                    # show the user running the pool
                    # suggest acl change to fix this problem
                    
                    if ($AppProcessmodel.identityType -eq "ApplicationPoolIdentity")
                    {
                        Write-Output "`r`nThe Application pool is running under: `"IIS APPPOOL\$($pool.name)`""
                    }
                    else
                    {
                        Write-Output "The Application pool is running under: $($AppProcessmodel.identityType)"
                    }   
                    
                    Write-Output ""       
                    
                    if (((Get-ACL "$potentialResource").Access | where IdentityReference -eq "BUILTIN\IIS_IUSRS").count -eq 0)
                    {
                        Show-PoshCommand -info "& icacls.exe `"$potentialResource`" /grant `"BUILTIN\IIS_IUSRS:RX`" " -intro "You may want to give read access to IIS_IUSRS"
                        Show-PoshCommand -info "& icacls.exe `"$webRoot`" /T /grant `"BUILTIN\IIS_IUSRS:(OI)(CI)(RX)`" " -intro "Or better, set read permission for the webroot to IIS_IUSRS"
                    }  
                    else
                    {                        
                        Show-PoshCommand -info "& icacls.exe `"$potentialResource`" /grant `"IUSR:RX`" " -intro "You may want to give read access to IUSR"
                        Show-PoshCommand -info "& icacls.exe `"$potentialResource`" /grant /T `"IUSR:(OI)(CI)(RX)`" " -intro "Or give read access to IUSR for the whole webroot folder"
                        Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location `'$($site.Name)`' -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'userName' -value ''" -intro "Or use the ApplicationPoolIdentity as user for anonymous access" 
                    }                                                  
                }
            }
            else
            {
                Write-Output "It seems in this version we have no information about how to fix your problem, sorry."
                Write-Verbose "It seems in this version we have no information about how to fix your problem, sorry."
            }

            if ($EnableFreb)
            {
                Enable-Tracing -siteId $site.id -siteName $site.Name -statuscodes $status -resource "*"
                Write-Output "Please run the same test again"
            }

            $filter = "system.applicationHost/sites/site[@name='" + $site.Name + "']/traceFailedRequestsLogging"
            $frebDir = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name "directory").Value

            $frebDir = [System.Environment]::ExpandEnvironmentVariables($frebDir)
            $frebDir = Join-Path $frebDir $("W3SVC" + $site.Id) 

            $frebFiles = Get-ChildItem $frebDir -Filter "fr*.xml" | Where LastWriteTime -gt $script:RequestStart.DateTime

            if ($frebFiles.count -gt 0)
            {
                Write-Host "Failed Request Tracing files are available:"
                $frebFiles | ForEach {Write-Host $_.FullName}
            }

      #      $frebDir
      #      $script:RequestStart

            Exit Get-ExitCode -status $status -sub $subStatus
        }
    }
    Process
    {

        $site = Get-ChildItem iis:\sites\ | Where name -eq $name

        if ($site -eq $null)
        {
            Write-Warning "WebSite $name not found"
            Exit 60015 # Not Found
        }
        else
        {
            Show-TestSuccess -info "WebSite: `"$name`" exists"
        }

        # Test WebSite is running
        if ($site.State -ne "Started")
        {
            Write-Warning "WebSite $name is not running"
            Write-Output "Please make sure the web site is running:"
            Show-PoshCommand "Start-WebSite `"$name`""
            Exit 60001
        }



        if ($DisableFreb)
        {
            Disable-Tracing -siteId $site.id -siteName $site.Name
        }

        Show-TestSuccess -info "WebSite: `"$name`" is running"

        $poolName = $site.applicationPool

        $pool = Get-Item IIS:\\AppPools\$poolName

        # the following two tests are not really required because
        # if the pool wouldn't exist or running, the site wouldn't run either.
        if ($pool -eq $null)
        {
            Write-Warning "Application Pool $poolName not found"
            Write-Output "Make sure your website has a existing application pool assigned"
            Exit 60010
        }
    
        if ($pool.State -ne "Started")
        {
            Write-Warning "Application pool $poolName is not running"
            Write-Output "Please make sure the Application pool is running:"
            Show-PoshCommand "Start-WebAppPool `"$poolName`""
            Exit 60011
        }
        
        $webRoot = [System.Environment]::ExpandEnvironmentVariables($site.PhysicalPath)

        $webConfig = Join-Path $webRoot "web.config"

        $webConfigTemplate = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
    </system.webServer>
</configuration>        
"@

        if (!(Test-path $webConfig))
        {
            Write-Warning "Web.Config file does not exists in the web root"
            Write-Output "Please make sure $webConfig exists."
          #  Show-PoshCommand -info "$webConfigTemplate | Set-Content $webConfig"

            $result = Confirm-Command -message "Create an empty web.config file now?"

            switch ($result)
            {
                0 {$webConfigTemplate | Set-Content $webConfig -Verbose}
                1 {}
            }

            Exit 60062
        }

        Show-TestSuccess -info "Configuration `"$webConfig`" exists"

        $script:RequestStart = Get-Date

        $failedRequests = New-Object 'System.Collections.Generic.dictionary[int64,string]'

        foreach($binding in $site.Bindings.collection)
        {
            # ignore non-http protocols
            if ($binding.protocol -match "^http")
            {
                $url = Convert-Binding -binding $binding
                $url += $Resource
                $ticks = [System.DateTime]::Now.Ticks
               
                $status = Test-WebPage -url $url -ticks $ticks

                if ($status -ne 200)
                {
                    $failedRequests.Add($ticks,$url)
                }            
            }

        }

        if ($failedRequests.Count -eq 0)
        {
            Show-TestSuccess -info "All test requests returned with status 200"
            Exit 20000
        }
        else
        {
            

            # flush logbuffer to see log entries right away
            & netsh http flush logbuffer | Out-Null

            $logfile = $site.logfile | Select -ExcludeProperty Logfile

            $filter = "system.applicationHost/sites/site[@name='" + $name + "']/logFile"

            if ($logfile.logFormat -ne "W3C")
            {
                Write-Warning "Please use W3C log format"
                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logFormat' -value 'W3C'"

                Exit 663            
            } 

            if ($logfile.period -ne "Daily")
            {
                Write-Warning "Please use Daily logs"            
                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'period' -value 'Daily'"
                Exit 60064            
            }

            if ($logfile.logExtFileFlags -notMatch "HttpSubStatus")
            {
                Write-Warning "Please include the sc-substatus field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",HttpSubStatus"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                Exit 60065            
            }

            if ($logfile.logExtFileFlags -notMatch "UserAgent")
            {
                Write-Warning "Please include the UserAgent field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",UserAgent"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                Exit 60066            
            } 
            
            if ($logfile.logExtFileFlags -notMatch "Win32Status")
            {
                Write-Warning "Please include the sc-Win32-Status field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",Win32Status"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                Exit 60065            
            }            
                   
        
            $logFileName = [System.Environment]::ExpandEnvironmentVariables($logfile.directory)
            $logFileName += "\W3SVC" + $site.Id + "\u_ex" + (Get-Date).ToString("yyMMdd") + ".log"

            if (!(Test-Path $logFileName))
            {
                Write-Warning "Log file not found: $logFileName" 
            }
            else
            {
                Write-Verbose "Checking $logFileName"
            }

            $Log = Get-Content $logFileName | where {$_ -notLike "#[D,S-V]*" }

            $fields = ""
            $statusColumn = 0

            foreach($request in $failedRequests.GetEnumerator())
            {
                $id = Get-UniqueUserAgent -ticks $request.Key           

                foreach ($Row in $Log) {

                    if ($row.StartsWith("#Fields"))
                    {
                        $fields = $row
                    }

                    if ($row -match $id)
                    {                  
                        $fieldColumns = $fields.Split(" ")
                        $statusColumn = [array]::IndexOf($fieldColumns, "sc-status")
                        $subStatusColumn = [array]::IndexOf($fieldColumns, "sc-substatus")
                        $win32StatusColumn = [array]::IndexOf($fieldColumns, "sc-win32-status")
                        $cols = $row.Split(" ") 

                        try
                        {
                            Process-Problem $webRoot $($request.Value) $($cols[$statusColumn-1]) $($cols[$subStatusColumn-1]) $($cols[$win32StatusColumn-1]) $pool $site                                    
                        }
                        catch
                        {
                            Write-Error $_.Exception.ToString()
                        }
                    }
                } # foreach row
            } # for each request
        } # end if requests
    } # end process

    End
    {
    }
