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
    Not supported yet
.PARAMETER install
    Installs required IIS components.
.PARAMETER SkipPrerequisitesChecks
    If specified, several checks for prerequisites are not performed. Because these cecks may take
    some time you can choose to skip them if you are sure you have them.
.PARAMETER DontOfferFixes
    If specified, the user will never be asked to run fixes. Useful for automated testing
.PARAMETER EnableFreb
    Enables Failed Request tracing, but just for the http status a problem was found for.
    Overrites previously existing tracing rules for the site.
.PARAMETER DisableFreb
    Disables Failed Request tracing for the site and removes all tracings rules.
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
  [ValidatePattern("^(http*|/[-\?/\.=&a-z0-9]*)")]
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

        $TestDataFullPath = "$env:SystemDrive\Inetpub\TestWebSiteTempData"
        $userAgentRoot = "Test-WebSite"

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
            
            # by default on a Server looking at the freb files doesn't work, by adding about:internet to the trusted zones, it should work. 
            # this will not be reversed by Disable-Tracing. Are there any side effects to this?            
            $null = New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains' -Force
            $null = New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\internet' -Force
            Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\internet' -Name about -Value 2 -Type DWord                        
        }

        Function Copy-FrebFiles([string]$file)
        {            
            if (!(Test-Path $TestDataFullPath))
            {    
                New-item -Path $TestDataFullPath -ItemType Directory | out-null
            }

            $orgFolder = [System.IO.Path]::GetDirectoryName($file)

            $xslFile = Join-Path $orgFolder "freb.xsl"
            $targetFrebFile = Join-Path $TestDataFullPath "freb.xsl"
            $dataFile = [System.IO.Path]::GetFileName($file)

            if (!(Test-Path $targetFrebFile))
            {
                Copy-Item $xslFile -Destination $targetFrebFile
            }

            $targetDataFile = Join-Path $TestDataFullPath $dataFile

            Copy-Item $file -Destination $targetDataFile -Force
            return $targetDataFile
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

        Function Show-TestSuccess([string]$info)
        {
            Write-Verbose "Test: $info "
        }          

        Function Get-UniqueUserAgent([int64]$ticks)
        {
            Return $userAgentRoot + "_" + $ticks.ToString()
        }

        Function Test-WebPage([string]$url)        
        {
            Write-verbose "Testing: $url"
            [int64]$ticks = [System.DateTime]::Now.Ticks
            $userAgent = Get-UniqueUserAgent -ticks $ticks

            try {
                $r = [System.Net.WebRequest]::Create($url)
                $r.UserAgent=$userAgent
                $resp = $r.GetResponse()            
                return $resp.StatusCode 
            }           
            catch [System.Net.WebException] 
            {              
                $resp = $_.Exception.Response

                if ($resp -eq $null)
                {
                    Write-Error $_.Exception
                    return 55400
                }
                else
                {
                    $reqstream = $resp.GetResponseStream()
                    $sr = New-Object System.IO.StreamReader $reqstream
                    $result = $sr.ReadToEnd()

                    # store the result in a global object
                    $script:FailedRequest = New-Object psobject -Property @{
                        Url = $url
                        Ticks = $ticks
                        Status = [int]$resp.StatusCode
                        Html = $result
                        }      
                    
                    return [int]$resp.StatusCode                
                }                    
                     
            } catch {            
                Write-Verbose $_.Exception
                return 55500
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
            $request,
            [int]$status,
            [int]$subStatus,
            [int]$win32Status,
            $pool,
            $site
            )
        
            $fullStatus = "$status.$subStatus"
            Write-Warning "$($request.Url) - $fullStatus - Win32: $win32Status"

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
            

            $res = $request.Url -replace "^https?://[^/]+", ""
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
                Write-Output "Make sure one of the defined default documents is present in the folder: `'$webRoot`'"
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

            if (Test-Path $frebDir)
            {
                $frebFiles = Get-ChildItem $frebDir -Filter "fr*.xml" | Where LastWriteTime -gt $script:RequestStart.DateTime

                if ($frebFiles.count -gt 0)
                {
                    Write-Host "Failed Request Tracing files are available:"
                    $frebFiles | ForEach {
                        Write-Output $(Copy-FrebFiles $_.FullName)
                    }
                }
            }

      #      $frebDir
      #      $script:RequestStart

            Exit Get-ExitCode -status $status -sub $subStatus
        }

        Function Check-Prerequisites
        {
            Write-Output "Checking prerequisites..."

            if (!($userIsAdmin))
            {
                Write-Warning "Please run this script as elevated administrator"
                Show-PoshCommand "Start-Process -Verb runas -FilePath $PSHOME\powershell.exe"
                Exit 40100 # Access denied.
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
            
                Exit 41200 # Precondition failed    
            }      
        }

        Function Get-Url($site,[string]$resource)
        {
            $url = ""

            if ($resource.StartsWith("http"))
            {
                return $resource
            }

            # this will return http:// before any https://
            # we may want to add more logic which binding to use later
            foreach($binding in ($site.Bindings.collection | Sort protocol | Select -First 1))
            {
                # ignore non-http protocols
                if ($binding.protocol -match "^http")
                {
                    $url = Convert-Binding -binding $binding
                    $url += $resource           
                }
            }

            return $url
        }

        Function Check-LogFile($site)
        {
            # this checks for log file settings which we would like to have
            # but we should work anyways

            $logfile = $site.logfile #| Select -ExpandProperty Logfile
            $filter = "system.applicationHost/sites/site[@name='" + $site.Name + "']/logFile"

            $logOkay = $true

            # check log file settings

            if ($logfile.logFormat -ne "W3C")
            {
                Write-Warning "Please use W3C log format"
                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logFormat' -value 'W3C'"
                $logOkay = $false           
            } 

            if ($logfile.period -ne "Daily")
            {
                Write-Warning "Please use Daily logs"            
                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'period' -value 'Daily'"
                $logOkay = $false            
            }

            if ($logfile.logExtFileFlags -notMatch "HttpSubStatus")
            {
                Write-Warning "Please include the sc-substatus field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",HttpSubStatus"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                $logOkay = $false           
            }

            if ($logfile.logExtFileFlags -notMatch "UserAgent")
            {
                Write-Warning "Please include the UserAgent field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",UserAgent"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                $logOkay = $false            
            } 
            
            if ($logfile.logExtFileFlags -notMatch "Win32Status")
            {
                Write-Warning "Please include the sc-Win32-Status field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",Win32Status"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                $logOkay = $false           
            }

            return $logOkay
        }

        Function Process-LogEntry($site)
        {
            # flush logbuffer to see log entries right away
            & netsh http flush logbuffer | Out-Null 

            $logfile = $site.logfile 
                           
            $logFileName = [System.Environment]::ExpandEnvironmentVariables($logfile.directory)
            $logFileName += "\W3SVC" + $site.Id + "\u_ex" + (Get-Date).ToString("yyMMdd") + ".log"

            if (!(Test-Path $logFileName))
            {
                Write-Warning "Log file not found: $logFileName" 
                Write-Output "This may happen if none of the bindings for the site work" 
                Write-Output "Try again using the verbose switch: Test-WebSite.ps1 -verbose "
            }
            else
            {
                Write-Verbose "Checking $logFileName"
            
                # we assume the entry we are looking for is the last one, so using -tail 50
                # gives us for few more, just in case.

                $Log = Get-Content $logFileName -Tail 50 | where {$_ -notLike "#[D,S-V]*" }

                $fields = ""
                $statusColumn = 0

                $id = Get-UniqueUserAgent -ticks $script:FailedRequest.Ticks          
                $lineFound = $false

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
                            Process-Problem  -webRoot $webRoot -request $request -Status $($cols[$statusColumn-1]) -SubStatus $($cols[$subStatusColumn-1]) -win32Status $($cols[$win32StatusColumn-1]) -pool $pool -site $site                                    
                            $script:requestProcessed = $false
                        }
                        catch
                        {
                            Write-Error $_.Exception.ToString()
                        }
                        $lineFound = $true
                        break
                    }
                } # foreach row

                if(!($lineFound))
                {
                    Write-output "No entry found in the logfile `'$logFileName`' to the request: $($request.Value)"
                    Process-Problem  -webRoot $webRoot -request $request -Status $request.Status -SubStatus 0 -win32Status 0 -pool $pool -site $site
                    $script:requestProcessed = $false
                }

                }   # log file found            
        }

        if ($install){Install-IISFeatures; exit 0}
        if (!($SkipPrerequisitesChecks)) {Check-Prerequisites}                
        Import-Module WebAdministration -Verbose:$false
        
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
             
        $url = Get-Url -site $site -resource $Resource
        $status = Test-WebPage -url $url

        if ($status -eq 200)
        {
            Show-TestSuccess -info "The test request returned with status 200"
            Write-Host "All tests passed" -ForegroundColor Green
            Exit 20000
        }
        else
        {      
            $script:requestProcessed = $false
            $logOkay = Check-LogFile -site $site

            if ($logOkay -eq $false)
            {
                Write-Warning "Log file settings not as required, log file will not be used"
            }
            else
            {      
                Process-LogEntry -site $site
            }

            if (!($script:requestProcessed))
            {
                Write-Host "Request could not be processed: http status: $status" -ForegroundColor Yellow
            }
        }
    }

    End
    {
    }
