<#
.SYNOPSIS
    Script to test an IIS website for the most common setup problems.
.DESCRIPTION
    The script tries to test a single IIS web site and will make suggestions on how
    to fix potential problems.
.PARAMETER Name
    The name of the web site to test, as seen in IIS Manager or 'Get-WebSite'
    If not provided 'Default Web Site' will be used.
.PARAMETER Resource
    the url part of the resource to test starting with the with slash after the hostname/port
    on the full url. Always start with a forward slash. If empty, the home page of the site will
    be tested.
    You can also specify a full address like http://www.mysite.com/index.php but is should resolve to the site you want to test.
    This way you can force testing multiple bindings of the site. 
.PARAMETER Mvc
    To indicate that the resource to be checked is expected to be handled by ASP.NET MVC
    Not supported yet
.PARAMETER Install
    Installs missing optional IIS components.
    Http logging and Failed Request Tracing
.PARAMETER Fix
    Try to fix problems found.
.PARAMETER Show
    Shows information about the web site, does not run any tests
.PARAMETER ShowServer
    Shows information about the IIS server, does not run any tests. Use -verbose for more information
.PARAMETER EnableFreb
    Enables Failed Request tracing for the site for all requests with a status of 400 or higher
    Overrites previously existing tracing rules for the site.
.PARAMETER DisableFreb
    Disables Failed Request tracing for the site and removes all tracings rules.
.PARAMETER OutputFile
    Specifies a file to write output to. Use this rather than piping the output into a file.
    Some information may get lost during piping.
.PARAMETER DontOfferFixes
    If specified, the user will never be asked to run fixes. Useful for automated testing
.PARAMETER BeStrict
   If specified, certain warnings will be considered stop-problems Useful for automated testing
.EXAMPLE       
    Test-WebSite
    Runs the tests against the web site named 'Default Web Site'
.EXAMPLE       
    Test-WebSite -Name MySite -Resource "/login.asp?user=foo" -OutputFile "~\documents\report.txt"
    Runs the tests against the specified resource on the web site named 'MySite'.
    Writes results to the console and also into the specified file.
.EXAMPLE       
    Test-WebSite -Name MySite -DontOfferFixes
    The script tests for the existance of a web.config file in the root of the site
    If it doesn't find it, it will offer to create and and then stops the script.
    If you don't want to create one and skip this test, use -DontOfferFixes
.EXAMPLE
    Test-WebSite -Name MySite -Resource "http://test.mysite.com/foo.html" -verbose
    Runs the tests against the specified resource on the web site named 'MySite'.
    The URL and the site bindings should match.
    Includes additional information about the tests performed
.EXAMPLE       
    Test-WebSite -ShowSite -name MySite
    Shows information for the web site named 'MySite'
.EXAMPLE       
    Test-WebSite -ShowServer
    Shows information about the web server including all sites and AppPools
.EXAMPLE       
    Test-WebSite -showServer -verbose
    Shows information about the web server including all sites and AppPools
    Includes information about the installed IIS modules
.EXAMPLE       
    Test-WebSite -name MySite -EnableFreb
    Enables 'Failed Request Tracing' for the site 'MySite'
    You can use this independent of running the test.
    When enabled, the result files will be available in a location accessible to a normal user.
.EXAMPLE       
    Test-WebSite -name MySite -DisableFreb
    Disables 'Failed Request Tracing' for the site 'MySite'

.NOTES

    The exit value is an integer number between 0 and 70000
    It is calculated by multiplying the http status times 100 and add the substatus
    So an normal 200-Okay is 20000
    a 404.8 is 40408
    a 500.19 is 50019

    Should work with PowerShell 2 on Windows 7 SP1 and anything newer

    Author:  Peter Hahndorf
    Created: July 1, 2015 
    
.LINK
    https://github.com/hahndorf/Test-WebSite   
#>

[CmdletBinding(DefaultParameterSetName="Test")] 
[OutputType([int])]
param(
  [parameter(Mandatory=$true,ParameterSetName = "ShowSite")]
  [switch]$ShowSite,
  [parameter(Mandatory=$true,ParameterSetName = "Server")]
  [switch]$ShowServer,
  [parameter(Mandatory=$true,ParameterSetName = "EnFreb")]
  [switch]$EnableFreb,
  [parameter(Mandatory=$true,ParameterSetName = "DisFreb")]
  [switch]$DisableFreb,
  [parameter(Mandatory=$true,ParameterSetName = "Install")]
  [switch]$Install,
  [Parameter(Position=0,ParameterSetName = "Test")]
  [parameter(ParameterSetName = "ShowSite")]
  [parameter(ParameterSetName = "DisFreb")]
  [parameter(ParameterSetName = "EnFreb")]
  [string]$Name = "Default Web Site",
  [ValidatePattern("^(http*|/[-\?/\.=&a-z0-9]*)")]
  [parameter(ParameterSetName = "Test")]
  [string]$Resource = "",
  [parameter(ParameterSetName = "Test")]
  [switch]$Fix,
  [parameter(ParameterSetName = "Test")]
  [switch]$Mvc,
  [parameter(ParameterSetName = "Test")]
  [switch]$DontOfferFixes,
  [parameter(ParameterSetName = "Test")]
  [switch]$BeStrict,
  [parameter(ParameterSetName = "Test")]
  [parameter(ParameterSetName = "ShowSite")]
  [parameter(ParameterSetName = "Server")]
  [string]$OutputFile = ""
)

    # we don't support input from the pipeline, we don't need begin, process, end
    # but we still use it to group the code, Begin has all the functions

    Begin
    {
    #    $myOS = Get-CimInstance -ClassName Win32_OperatingSystem -Namespace root/cimv2
        $myOS = Get-WmiObject -Class Win32_OperatingSystem

        $statusInfo = New-Object 'System.Collections.Generic.dictionary[string,string]'
        $statusInfo.Add("404.0","The file that you are trying to access does not exist")
        $statusInfo.Add("404.3","The current MIME mapping for the requested extension type is not valid or is not configured.")
        $statusInfo.Add("401.3","This HTTP status code indicates a problem in the NTFS file system permissions. This problem may occur even if the permissions are correct for the file that you are trying to access. For example, this problem occurs if the IUSR account does not have access to the C:\Winnt\System32\Inetsrv directory. For more information about how to resolve this problem, check the article in the Microsoft Knowledge Base: 942042 ")
        $statusInfo.Add("500.19","The related configuration data for the page is invalid or can not be accessed.")

        # taken from: https://support2.microsoft.com/default.aspx?scid=kb;en-us;820729
        $ReasonPhrase = New-Object 'System.Collections.Generic.dictionary[string,string]'
        $ReasonPhrase.Add("AppOffline","A service unavailable error occurred (an HTTP error 503). The service is not available because application errors caused the application to be taken offline.")
        $ReasonPhrase.Add("AppPoolTimer","A service unavailable error occurred (an HTTP error 503). The service is not available because the application pool process is too busy to handle the request.")
        $ReasonPhrase.Add("AppShutdown","A service unavailable error occurred (an HTTP error 503). The service is not available because the application shut down automatically in response to administrator policy.")
        $ReasonPhrase.Add("BadRequest","A parse error occurred while processing a request.")
        $ReasonPhrase.Add("Client_Reset","The connection between the client and the server was closed before the request could be assigned to a worker process. The most common cause of this behavior is that the client prematurely closes its connection to the server.")
        $ReasonPhrase.Add("Connection_Abandoned_By_AppPool","A worker process from the application pool has quit unexpectedly or orphaned a pending request by closing its handle.")
        $ReasonPhrase.Add("Connection_Abandoned_By_ReqQueue","A worker process from the application pool has quit unexpectedly or orphaned a pending request by closing its handle. Specific to Windows Vista and later versions and to Windows Server 2008 and later versions.")
        $ReasonPhrase.Add("Connection_Dropped","The connection between the client and the server was closed before the server could send its final response packet. The most common cause of this behavior is that the client prematurely closes its connection to the server.")
        $ReasonPhrase.Add("Connection_Dropped_List_Full","The list of dropped connections between clients and the server is full. Specific to Windows Vista and later versions and to Windows Server 2008 and later versions.")
        $ReasonPhrase.Add("ConnLimit","A service unavailable error occurred (an HTTP error 503). The service is not available because the site level connection limit has been reached or exceeded.")
        $ReasonPhrase.Add("Connections_Refused","The kernel NonPagedPool memory has dropped below 20MB and http.sys has stopped receiving new connections")
        $ReasonPhrase.Add("Disabled","A service unavailable error occurred (an HTTP error 503). The service is not available because an administrator has taken the application offline.")
        $ReasonPhrase.Add("EntityTooLarge","An entity exceeded the maximum size that is permitted.")
        $ReasonPhrase.Add("FieldLength","A field length limit was exceeded.")
        $ReasonPhrase.Add("Forbidden","A forbidden element or sequence was encountered while parsing.")
        $ReasonPhrase.Add("Header","A parse error occurred in a header.")
        $ReasonPhrase.Add("Hostname","A parse error occurred while processing a Hostname.")
        $ReasonPhrase.Add("Internal","An internal server error occurred (an HTTP error 500).")
        $ReasonPhrase.Add("Invalid_CR/LF","An illegal carriage return or line feed occurred.")
        $ReasonPhrase.Add("LengthRequired","A required length value was missing.")
        $ReasonPhrase.Add("N/A","A service unavailable error occurred (an HTTP error 503). The service is not available because an internal error (such as a memory allocation failure or URL Reservation List conflict) occurred.")
        $ReasonPhrase.Add("N/I","A not-implemented error occurred (an HTTP error 501), or a service unavailable error occurred (an HTTP error 503) because of an unknown transfer encoding.")
        $ReasonPhrase.Add("Number","A parse error occurred while processing a number.")
        $ReasonPhrase.Add("Precondition","A required precondition was missing.")
        $ReasonPhrase.Add("QueueFull","A service unavailable error occurred (an HTTP error 503). The service is not available because the application request queue is full.")
        $ReasonPhrase.Add("RequestLength","A request length limit was exceeded.")
        $ReasonPhrase.Add("Timer_AppPool","The connection expired because a request waited too long in an application pool queue for a server application to de-queue and process it. This time-out duration is <b>ConnectionTimeout</b>. By default, this value is set to two minutes.")
        $ReasonPhrase.Add("Timer_ConnectionIdle","The connection expired and remains idle. The default <b>ConnectionTimeout</b> duration is two minutes.")
        $ReasonPhrase.Add("Timer_EntityBody","The connection expired before the request entity body arrived. When a request clearly has an entity body, the HTTP API turns on the <b>Timer_EntityBody</b> timer. At first, the limit of this timer is set to the <b>ConnectionTimeout</b> value (typically, two minutes). Every time that another data indication is received on this request, the HTTP API resets the timer to give the connection two more minutes (or whatever is specified in <b>ConnectionTimeout</b>).")
        $ReasonPhrase.Add("Timer_HeaderWait","The connection expired because the header parsing for a request took more time than the default limit of two minutes.")
        $ReasonPhrase.Add("Timer_MinBytesPerSecond","The connection expired because the client was not receiving a response at a reasonable speed. The response send rate was slower than the default of 240 bytes/sec. This can be controlled with the <b>MinFileBytesPerSec</b> metabase property.")
        $ReasonPhrase.Add("Timer_ReqQueue","The connection expired because a request waited too long in an application pool queue for a server application to de-queue. This time-out duration is <b>ConnectionTimeout</b>. By default, this value is set to two minutes. Specific to Windows Vista and later versions and to Windows Server 2008 and later versions.")
        $ReasonPhrase.Add("Timer_Response","Reserved. Currently not used.")
        $ReasonPhrase.Add("Timer_SslRenegotiation","The connection expired because SSL renegotiation between the client and server took longer than the default time-out of two minutes.")
        $ReasonPhrase.Add("URL","A parse error occurred while processing a URL.")
        $ReasonPhrase.Add("URL_Length","A URL exceeded the maximum permitted  size.")
        $ReasonPhrase.Add("Verb","A parse error occurred while processing a verb.")
        $ReasonPhrase.Add("Version_N/S","A version-not-supported error occurred (an HTTP error 505). ")

        $TestDataFullPath = "$env:SystemDrive\Inetpub\TestWebSiteTempData"
        $userAgentRoot = "Test-WebSite"

        [int]$separatorWith = 70

        # exit codes
        [int]$ExitSuccess = 0
        [int]$WebSuccess = 20000
        [int]$ExitAccessDenied = 40100 
        [int]$OSVersionNotSupported = 60198 
        [int]$AppPoolNotFound = 60010 
        [int]$WebSiteNotRunning = 60001
        [int]$AppPoolNotRunning = 60011
        [int]$NoUrlProvided = 60013 
        [int]$NoBindingFound = 60014 
        [int]$WebSiteNotFound = 60015 
        [int]$PowerShellVersionNotSupported = 60018 
        [int]$WebAdministrationModuleMissing = 60019
        [int]$WebConfigMissing = 60062  
      
        # Infrastucture functions

        Function Publish-TextToFile([string]$text)
        {
            if ($OutputFile -ne "")
            {
                $text | Out-File $OutputFile -Append
            }
        }

        Function Publish-Verbose([string]$text)
        {
            if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent)
            {
                Publish-TextToFile -text "VERBOSE: $text"
            }
            Write-Verbose "$text"
        }

        Function Publish-Warning([string]$text)
        {
            Publish-TextToFile -text "WARNING: $text"
            Write-Warning "$text"
        }

        Function Publish-Text([string]$text)
        {
            Publish-TextToFile -text $text
            Write-Host "$text"
        }

        Function Publish-SuccessText([string]$text)
        {
            Publish-TextToFile -text "Success: $text"
            Write-Host "$text" -ForegroundColor Green
        }

        Function Publish-FailureText([string]$text)
        {
            Publish-TextToFile -text "Failure: $text"
            Write-Host "$text" -ForegroundColor Red -BackgroundColor Black
        }

        Function Get-WinFeatures()
        {
            # this works on Windows 7+
            Write-Host "Checking installed Windows features..."
            $tempFile = "$env:temp\TestWindowsFeature.log"
            & dism.exe /online /get-features /format:table | out-file $tempFile -Force       
            $Script:WinFeatures = (Import-CSV -Delim '|' -Path $tempFile -Header Name,state | Where-Object {$_.State -eq "Enabled "}) | Select Name
            Remove-Item -Path $tempFile            
        }

        Function Get-ExitCode([int]$status,[int]$sub)
        {
            return ($status * 100) + $sub
        }

        Function Show-PoshCommand([string]$info,[string]$intro)
        {
            $info | clip
            if ($intro -ne $null)
            {
                Publish-Text -text "Suggested Command: $intro"
            }
            else
            {
                Write-Host "You may use the following command:"
            }
            Write-Host $info -ForegroundColor Black -BackgroundColor Gray
            Write-Host "This command has been copied to your clipboard"
        }

        Function Install-IISFeature([string]$name,[switch]$skipTest)
        {
            if (!($skipTest)) 
            {
                if (Test-WindowsFeature -Name $name)
                {
                    Publish-Text "$name is already installed"
                    return
                }
            }

            Write-Output "Running: -online -enable-feature -featurename:$name"
            dism.exe -online -enable-feature -featurename:$name       
        }

        Function Check-RequiredPrerequisites
        {
            $UserCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $userIsAdmin = $false
            $UserCurrent.Groups | ForEach-Object { if($_.value -eq "S-1-5-32-544") {$userIsAdmin = $true} }

            if (!($userIsAdmin))
            {
                Write-Warning "Please run this script as elevated administrator"
                Show-PoshCommand "Start-Process -Verb runas -FilePath $PSHOME\powershell.exe"
                Exit $ExitAccessDenied
            }

            if ([int]$myOS.BuildNumber -lt 7601)
            {   
                Publish-Warning -text  "Your OS version is not supported" 
                Exit $OSVersionNotSupported
            }

            if ([int]$PSVersionTable.PSVersion.Major -lt 2)
            {
                Publish-Warning -text "PowerShell version 2 or newer is required to run this script"
                Exit $PowerShellVersionNotSupported
            }            

            if(!(Get-Module -ListAvailable -Name WebAdministration))
            { 
                Publish-Warning -text "The required WebAdministration module is missing."
                Show-PoshCommand "Test-WebSite -fix" "Please run:"
                if ($fix)
                {
                    Install-IISFeature -name IIS-ManagementScriptingTools -skipTest
                }
                Exit $WebAdministrationModuleMissing
            }              
        }

        Function Install-OptionalTools
        {
            Get-WinFeatures
            Install-IISFeature -name IIS-HttpLogging
            Install-IISFeature -name IIS-HttpTracing 
        }

        Function Test-WindowsFeature()
        {
            Param
            (
                [Parameter(Mandatory=$true,Position=0)]
                $Name
            )
               
            $feature = ($Script:WinFeatures | Where-Object {$_.Name.Trim() -eq $name})

            if ($feature -ne $null)
            {
                return $true
            }
            else
            {
                return $false
            }
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

            Write-Host "Enabling failed request tracing for $resource requests with $statusCodes status for site: `'$siteName`'"

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

            Write-Host "Disabling failed request tracing for site `'$siteName`'"

            $psPath = "MACHINE/WEBROOT/APPHOST/$siteName"

            # clear any existing stuff
            Remove-WebConfigurationProperty -pspath $psPath  -filter "system.webServer/tracing/traceFailedRequests" -name "."
                       
        }

        # Show Information functions

        Function Print-Attribute([string]$caption,[string]$value)
        {
            $caption = $caption + ":"
            $caption = $caption.PadRight(23," ")

            Publish-Text -text "$caption $value" 
        }

        Function Print-Stuff($stuff)
        {
            Publish-Text -text $stuff
        }

        Function Print-SectionHeader($text)
        {
            Print-Stuff ""
            Print-Stuff ("=" * $separatorWith)
            Print-Stuff "$text"
            Print-Stuff ("=" * $separatorWith)
            Print-Stuff ""
        }

        Function Print-SubHeader($text)
        {
            Print-Stuff ""
            Print-Stuff "$text"
            Print-Stuff ("-" * $separatorWith)
        }

        Function Show-MainObjects()
        {
            Print-SectionHeader "Web Sites:"
            Publish-Text -text (Get-ChildItem IIS:\Sites| Out-String).Trim()
            Print-SectionHeader "Application Pools:"
            Publish-Text -text (Get-ChildItem IIS:\AppPools | FT | Out-String).Trim()
            Print-SectionHeader "SSL Bindings:"
            Publish-Text -text (Get-ChildItem IIS:\SslBindings | Out-String).Trim()
            Print-SectionHeader "TLS Server Certificates: $((Get-ChildItem Cert:\LocalMachine\my | Where-Object {$_.EnhancedKeyUsageList -match "Server Authentication"}).Count)"
            
            Publish-Text -text (netsh http show iplisten | Out-string).Trim()
        }

        Function Show-OSInfo()
        {
            Print-SubHeader "Test-WebSite output - $((Get-Date).ToString("d MMMM yyyy HH:mm:ss"))"

            Print-SectionHeader "Operating System:"

            $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
          #  $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Namespace root/cimv2
            $webRoot = [System.Environment]::ExpandEnvironmentVariables($site.PhysicalPath)

            Print-Attribute "Caption" $($OSInfo.Caption)
            Print-Attribute "Version" $($OSInfo.Version)
            Print-Attribute "SystemDirectory" $($OSInfo.SystemDirectory)
            Print-Attribute "OSArchitecture" $($OSInfo.OSArchitecture)
            Print-Attribute "MUILanguages" $($OSInfo.MUILanguages)                    
         }

        Function Show-ServerInfo()
        {
            Show-OSInfo
            Show-MainObjects
            if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent)
            {
                Show-IISInfo
            }
        }

        Function Show-IISInfo()
        {
            Print-SectionHeader "information about IIS:"

            Print-SubHeader "Installed IIS Components"

            # works in 6.2 and newer only
            # Get-WindowsOptionalFeature –Online | Where {$_.FeatureName -match "^IIS-" -and $_.State -eq "Enabled"} | Sort FeatureName | Select FeatureName | Format-Table -HideTableHeaders

            # the following works in Win7/2008R2 and newer           
            $tempFile = "$env:temp\TestWindowsFeature.log"
            & dism.exe /online /get-features /format:table | out-file $tempFile -Force       
            Publish-Text -text (Import-CSV -Delim '|' -Path $tempFile -Header Name,state | Where-Object {$_.Name.Trim() -match "^IIS-" -and $_.State.Trim() -eq "Enabled"} | Sort Name | Select Name | Format-Table -HideTableHeaders | Out-String).Trim()
            Remove-Item -Path $tempFile -Force

            Print-SubHeader "Global Modules"
            
            Publish-Text -text ((Get-WebConfiguration //globalmodules -PSPath "iis:\").collection | Sort-Object Name | Select Name | Format-Table -HideTableHeaders | Out-String).Trim()     
        }

        Function Show-SiteInfo($site,$pool)
        {
            $webRoot = [System.Environment]::ExpandEnvironmentVariables($site.PhysicalPath)           

            Print-SectionHeader "Web Site"

            Print-Attribute "Name" $($site.name)
            Print-Attribute "PhysicalPath" $webRoot         
            
            Print-SubHeader "Bindings"

            Publish-Text -text (($site | Select -expandproperty bindings).collection | format-table -AutoSize | Out-String).Trim()
            
            $limits = ($site | Select -expandproperty limits).collection
            if ($limits.count -gt 0)
            {
                Print-SubHeader "Limits"
                Publish-Text -text ($limits |format-table -AutoSize | Out-String).Trim()
            }

            Print-SubHeader "Default Documents"
            Publish-Text -text (Get-WebConfiguration "system.webserver/defaultdocument/files/*" "IIS:\sites\$($site.Name)" | Select value | Format-Table -HideTableHeaders  | Out-String).Trim()

            Print-SubHeader "Error Pages"
            Publish-Text -text (Get-WebConfiguration "system.webserver/httpErrors" "IIS:\sites\$($site.name)" | Format-Table -Property ErrorMode,existingResponse,defaultResponseMode  -AutoSize | Out-String).Trim()

            Print-SubHeader "Authentication"
            Get-WebConfiguration "system.webserver/security/authentication/*" "IIS:\sites\$($site.Name)" | Sort-Object SectionPath | foreach{
                 Publish-Text -text ""
                 Publish-Text -text $($_.SectionPath -replace "/system.webServer/security/authentication/","")
                 Publish-Text -text ""
                 Publish-Text -text ($_ | select -expandproperty attributes | Where {$_.Name -ne "password"} | Select Name,Value | Format-Table -AutoSize | out-string).Trim()
            }

            Show-PoolInfo $pool

            Print-SectionHeader "NTFS permissions"

            Print-SubHeader "Folder permissions for $webRoot"

            Publish-Text -text ((Get-ACL $webRoot).Access | Sort-Object IdentityReference | Select IdentityReference, FileSystemRights, AccessControlType, IsInherited | Format-Table -AutoSize | out-string).Trim()

            $virDirs = Get-WebVirtualDirectory -site "$($site.name)"

            if ($virDirs.count -gt 0)
            {
                Print-SectionHeader "Virtual Directories"
                Publish-Text -text ($virDirs | Format-Table -Property Path,PhysicalPath,AllowSubDirConfig,UserName  -AutoSize | Out-String).Trim()
            }

            $apps = Get-WebApplication -site "$($site.name)"
            
            if ($apps.count -gt 0)
            {
                Print-SectionHeader "Applications"
                Publish-Text -text ($apps | Select Path,PhysicalPath,applicationPool | Format-Table -AutoSize | Out-String).Trim()
            }
         }

        Function Show-PoolInfo($pool)
        {
            Print-SectionHeader "Application Pool"

            Print-Attribute "Name" $($pool.name)
            Print-Attribute "autoStart" $($pool.autoStart)
            Print-Attribute "enable32BitAppOnWin64" $($pool.enable32BitAppOnWin64)
            Print-Attribute "managedRuntimeVersion" $($pool.managedRuntimeVersion)
            Print-Attribute "managedPipelineMode" $($pool.managedPipelineMode)
            
            Print-Attribute "startMode" $($pool.startMode)

            $pm = $pool | select -expandproperty processModel

            Print-Attribute "identityType" $pm.identityType
            Print-Attribute "userName" $pm.userName
            Print-Attribute "loadUserProfile" $pm.loadUserProfile
            Print-Attribute "setProfileEnvironment" $pm.setProfileEnvironment
            Print-Attribute "LogonType" $pm.logonType
            Print-Attribute "ManualGroupMembership" $pm.manualGroupMembership            
        }

        Function Show-Site([string]$name)
        {
            $site = Get-ChildItem iis:\sites\ | Where {$_.name -eq "$name"}
            if ($site -eq $null)
            {
                Publish-Warning -text "The WebSite `'$name`' could not found"

                Publish-Text "Existing sites on this server:"
                Get-ChildItem iis:\sites | Select Name | Format-Table -HideTableHeaders -AutoSize

                Exit $WebSiteNotFound
            }

            $poolName = $site.applicationPool
            $pool = Get-Item "IIS:\\AppPools\$poolName"

            if ($pool -eq $null)
            {
                Publish-Warning -text "Application Pool $poolName not found"
                Publish-Text -text "Make sure your website has a existing application pool assigned"
                Exit $AppPoolNotFound
            }

            Show-OSInfo

            Show-SiteInfo -site $site -pool $pool 

        }

        # Output Helper Functions

        Function Show-TestSuccess([string]$info)
        {
            Publish-Verbose -Text "Test: $info "
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

        Function Get-UniqueUserAgent([int64]$ticks)
        {
            Return $userAgentRoot + "_" + $ticks.ToString()
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
       
        Function Get-Url($site,[string]$resource)
        {
            $url = ""

            # we allow to specify the full uri, even if it doesn't match the binding.
            if ($resource.StartsWith("http"))
            {
                return $resource
            }

            # this will return http:// before any https://
            # and then picks the first one in order
            foreach($binding in ($site.Bindings.collection | Sort-Object protocol, bindingInformation))
            {
                Publish-Verbose -Text "checking binding: $($binding.ToString())"

                # ignore non-http protocols
                if ($binding.protocol -match "^http")
                {
                    $url = Convert-Binding -binding $binding
                    $url += $resource
                    break        
                }
            }

            if ($url -eq "")
            {
                Publish-Warning -text "No valid binding found, only http* is supported"
                Exit $NoBindingFound
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
                Publish-Warning -text "Please use W3C log format"
                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logFormat' -value 'W3C'"
                $logOkay = $false           
            } 

            if ($logfile.period -ne "Daily")
            {
                Publish-Warning -text "Please use Daily logs"            
                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'period' -value 'Daily'"
                $logOkay = $false            
            }

            if ($logfile.logExtFileFlags -notMatch "HttpSubStatus")
            {
                Publish-Warning -text "Please include the sc-substatus field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",HttpSubStatus"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                $logOkay = $false           
            }

            if ($logfile.logExtFileFlags -notMatch "UserAgent")
            {
                Publish-Warning -text "Please include the UserAgent field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",UserAgent"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                $logOkay = $false            
            } 
            
            if ($logfile.logExtFileFlags -notMatch "Win32Status")
            {
                Publish-Warning -text "Please include the sc-Win32-Status field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",Win32Status"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                $logOkay = $false           
            }

            return $logOkay
        }

        Function Get-LogContent([string]$fileName,[int]$tail,[string]$exclude)
        {
            if ([int]$PSVersionTable.PSVersion.Major -lt 30)
            {
                return (Get-Content $fileName | Where-Object {$_ -notLike $exclude}) | Select -Last $tail
            }
            else
            {
                return Get-Content $fileName -Tail $tail | Where-Object {$_ -notLike $exclude}
            } 
        }

        # Main Process functions

        Function New-EmptyWebConfig([string]$webConfig)
        {

        $webConfigTemplate = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
    </system.webServer>
</configuration>        
"@

            $webConfigTemplate | Set-Content $webConfig -Verbose

        }

        Function Test-WebConfig([string]$webRoot)
        {
            $webConfig = Join-Path $webRoot "web.config"

            if (!(Test-path $webConfig))
            {
                Publish-Warning -text "Web.Config file does not exists in the web root"
                Publish-Text -text "Please make sure $webConfig exists."
                $result = Confirm-Command -message "Create an empty web.config file now?"

                switch ($result)
                {
                    0 {New-EmptyWebConfig -webConfig $webConfig}
                    1 {}
                }

                # if the user wants to be script, this is an exit condition
                if ($BeStrict)
                {
                    Publish-Text -text "Exit script, don't use -BeStrict to continue"
                    Exit $WebConfigMissing
                }
            }
            else
            {
                Show-TestSuccess -info "Configuration `"$webConfig`" exists"   
            }                     
        }

        Function Process-Page($site)
        {
            $html = $script:FailedRequest.Html

            Publish-Verbose -Text "Analyzing error page html"

            if ($html.Length -lt 1000)
            {
                if ($script:FailedRequest.Server -eq "Microsoft-HTTPAPI/2.0")
                {
                    Publish-Warning -text "IIS was unable to find a running application pool"
                                   
                    # https://support2.microsoft.com/default.aspx?scid=kb;en-us;820729

                    # it seems the httperr log is only flushed to disk every minute or so, at least sometimes it takes more than 20 seconds
                    # we can not wait for that, but it is likely that previous entries show the same problem

                    # the logs may have moved, HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP\Parameters\ErrorLoggingDir
                    $logFileName = (Get-ChildItem $env:systemRoot\system32\LogFiles\HTTPERR\ | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

                    if ($logFileName -ne $null)
                    {
                        Publish-Verbose -Text "Checking http.sys log: $logFileName"
                        $Log = Get-LogContent -fileName $logFileName -tail 5 -exclude "#*"  # Get-Content $logFileName -Tail 5 | Where-Object {$_ -notLike "#*" }
                        Publish-Verbose -Text "Here are the last lines, time is in UTC" 
                        Publish-Verbose -Text "Please note that this log is not up to date, but the problem may be listed anyways"
                        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent)
                        {         
                            $Log
                        }
                        # store the last line in the html field to be used later
                        $script:FailedRequest.html = $Log | Select -Last 1
                    }                    
                }   
                else
                {
                    Publish-Warning -text "Short response, but not from Microsoft-HTTPAPI/2.0, what can it be?"
                }             
            }
            else
            {
                # this may only work for IIS 8.x
                $html = $html -replace "&nbsp;",""
                $html = $html -replace "&raquo;",""         
                $xml = [Xml]$html                
          
                if ( ($xml.html.body.div.div.h3).count -eq 0)
                {
                    Publish-Warning -text "Detailed local error messages seem not to be enabled"
                    Show-PoshCommand -info "Set-WebConfigurationProperty -pspath `'MACHINE/WEBROOT/APPHOST/$($site.Name)`'  -filter `"system.webServer/httpErrors`" -name `"errorMode`" -value `"DetailedLocalOnly`""
                    return
                }

                $script:FailedRequest.SubStatus = [regex]::match($xml.html.body.div.div.h3,'\d{3}.(\d{1,3})').Groups[1].Value
                if ( ($xml.html.body.div.div[3].fieldset.div.table.tr).count -gt 2)
                {
                     $script:FailedRequest.Win32 = $xml.html.body.div.div[3].fieldset.div.table.tr[3].td
                }
            }
            
            # we could get other information from the page

            $script:FailedRequest.Processed = $true
            
        }

        Function Process-LogEntry($site)
        {
            $logOkay = Check-LogFile -site $site
            if ($logOkay -eq $false)
            {
                 Publish-Warning -text "Log file settings not as required, log file will not be used"
                 return
            }

            # flush logbuffer to see log entries right away
            & netsh http flush logbuffer | Out-Null 

            $logfile = $site.logfile 
                           
            $logFileName = [System.Environment]::ExpandEnvironmentVariables($logfile.directory)
            $logFileName += "\W3SVC" + $site.Id + "\u_ex" + (Get-Date).ToString("yyMMdd") + ".log"

            if (!(Test-Path $logFileName))
            {
                Publish-Warning -text "Log file not found: $logFileName" 
                Publish-Text -text" This may happen if none of the bindings for the site work" 
                Publish-Text -text "Try again using the verbose switch: Test-WebSite.ps1 -verbose "
                Return
            }
           
            Publish-Verbose -Text "Checking $logFileName"
            
            # we assume the entry we are looking for is the last one, so using -tail 50
            # gives us for few more, just in case.

            $Log = Get-Content $logFileName -Tail 50 | where {$_ -notLike "#[D,S-V]*" }

            $fields = ""
            $statusColumn = 0

            $id = Get-UniqueUserAgent -ticks $script:FailedRequest.Ticks   
                
            Publish-Verbose -Text "looking for row with: $id"
                       
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

                    $script:FailedRequest.SubStatus = $cols[$subStatusColumn-1]
                    $script:FailedRequest.Win32 = $cols[$win32StatusColumn-1]
                    $script:FailedRequest.Processed = $true

                    Publish-Verbose -Text "Found: $row"
                    $lineFound = $true
                    break
                }
            } # foreach row

            if(!($lineFound))
            {
                WPublish-Text -text "No entry found in the logfile `'$logFileName`' to the request: $($request.Value)"
            }                         
        }
       
        Function Test-WebPage([string]$url)
        {

            if ($url -eq $null -or $url -eq "")
            {
                Publish-Warning -text "Unable to find a URL to use for testing"
                Exit $NoUrlProvided
            }

            Publish-Verbose -Text "Testing: $url"
            [int64]$ticks = [System.DateTime]::Now.Ticks
            $userAgent = Get-UniqueUserAgent -ticks $ticks

            try {
                $r = [System.Net.WebRequest]::Create($url)
                $r.UserAgent=$userAgent
                $resp = $r.GetResponse()        
     
                if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent)
                {        
                    Publish-Verbose -Text "Response Headers:" 
                    foreach ($HeaderKey in $resp.Headers) {
                          $caption = $HeaderKey.PadLeft(15," ")
                          Publish-Text "$caption`: $($resp.Headers[$HeaderKey])";
                    }
                }
                    
                if ($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
                {        
                    $reqstream = $resp.GetResponseStream()
                    $sr = New-Object System.IO.StreamReader $reqstream
                    $result = $sr.ReadToEnd()
                    Write-Debug "$result"
                }

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

                    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent)
                    {        
                        Publish-Verbose -Text "Response Headers:" 
                        Publish-Text "         Status: $([int]$resp.StatusCode) - $($resp.StatusCode)"
                        foreach ($HeaderKey in $resp.Headers) {
                              $caption = $HeaderKey.PadLeft(15," ")
                              Publish-Text "$caption`: $($resp.Headers[$HeaderKey])";
                        }

                        Write-Debug "$result"
                    }

                    # store the result in a global object
                    $script:FailedRequest = New-Object psobject -Property @{
                        Url = $url
                        Ticks = $ticks
                        Status = [int]$resp.StatusCode
                        SubStatus = 0
                        Win32 = 0
                        Processed = $false
                        Html = $result
                        Server = $resp.Headers["Server"] 
                        ContentLength = $resp.Headers["Content-Length"] 
                        ContentType = $resp.Headers["Content-Type"]
                        }      
                    
                    return [int]$resp.StatusCode                
                }                    
                     
            } catch {            
                Publish-Verbose -Text $_.Exception
                return 55500
            }
        }

        Function Process-Problem
        {
            [OutputType([int])]
            param(
            [string]$webRoot,
            $pool,
            $site
            )       

            $fullStatus = "$($script:FailedRequest.Status).$($script:FailedRequest.SubStatus)"
            Publish-FailureText -text "$($script:FailedRequest.Url) - $fullStatus - Win32: $($script:FailedRequest.Win32)"

            if ($statusInfo.ContainsKey($fullStatus))
            {
                Publish-Warning -text $statusInfo[$fullStatus]
            }
            else
            {
           #     Publish-Warning -text "This problem is currently not handled"
            }

            # use content from files in C:\inetpub\custerr\en-US
            # to display some information about the problem
            

            $res = $script:FailedRequest.Url -replace "^https?://[^/]+", ""
            $res = $res -replace "/","\"
            $potentialResource = Join-Path $webRoot $res

            Publish-Verbose -Text "Physical Resource: $potentialResource"

            $AppProcessmodel = ($pool | Select -ExpandProperty processmodel)
            $webRoot = [System.Environment]::ExpandEnvironmentVariables($site.PhysicalPath)

            try
            {
                $defaultDocs = Get-WebConfiguration "system.webserver/defaultdocument/files/*" "IIS:\sites\$($site.Name)" | Select value    
            }
            catch
            {
                Publish-Warning -text "A problem occurred reading the configuration"
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

            Publish-Text -Text ""

            # display content from the IIS error pages
            # there may be more than one language we just pick the random first one
            $errorPageDir = Get-ChildItem $env:SystemDrive\inetpub\custerr\ | select -First 1
            # get the full file name for the error page
            $errorPageFile = $script:FailedRequest.Status.ToString() + "-" + $script:FailedRequest.SubStatus.ToString() + ".htm"
            $errorPageFile = Join-Path $errorPageDir.FullName $errorPageFile

            if (Test-Path $errorPageFile)
            {
                Publish-Text -text "----------------------------------------------------------------------"
                Publish-Text -text "Additional Information:"
                [xml]$errorPage = Get-Content $errorPageFile
                Publish-Text -text $errorPage.html.body.div.div.fieldset.h2
                Publish-Text -text $errorPage.html.body.div.div.fieldset.h3
                Publish-Text -text "----------------------------------------------------------------------"
            }

            Publish-Text "Suggested solution:"

            if ($fullStatus -eq "404.0")
            {
                Publish-Text -text "The file `'$potentialResource`' does not exists on disk, please double check the location."
            }
            elseif ($fullStatus -eq "403.14")
            {
                Publish-Text -text "Make sure one of the defined default documents is present in the folder: `'$webRoot`'"
                $defaultDocs | ForEach {
                    Publish-Text -text " - $($_.value) "
                }
                Publish-Text -text "We do not recommend to enable directory browsing"
            }            
            elseif ($fullStatus -eq "404.3")
            {
                If (Test-Path $potentialResource)
                {
                    $extension = [System.IO.Path]::GetExtension($potentialResource)

                    Publish-Text -text "The file $potentialResource exists, but IIS is not configured to serve files with the extension `'$extension`'"
                    Show-PoshCommand "Add-WebConfigurationProperty -pspath `'MACHINE/WEBROOT/APPHOST/$($site.Name)`' -filter 'system.webServer/staticContent' -name '.' -value @{fileExtension=`'$extension`';mimeType='text/html'}" `
                    -intro "Add a new MIME type, but make sure your are using the correct type for this file"
                }
            }
            elseif ($fullStatus -eq "500.19")
            {             
                if ($win32Status -eq 5)
                {
                    Publish-Text -text "Set permissions on web.config"
                } 
                elseif ($win32Status -eq 50)
                {
                    Publish-Text -text "Problem with the Configuration"
                }  
            }
            elseif ($fullStatus -eq "503.0")
            {             
                Publish-Text -text "Service Unavailable"
                
                Publish-Text -text "There are many potential reasons for this problem"
                Publish-Text -text "If you are running a custom application, please check the Windows event logs"

                $pastSeconds = 10
                $time = (Get-Date) – (New-TimeSpan -Minute $pastSeconds)

                # never get more than 50 events
                $errorEvents = Get-WinEvent -MaxEvents 50 -FilterHashtable @{Level=2;logname='application';StartTime=$time}  -Verbose:$false

                if ($errorEvents.Count -gt 0)
                {
                  Publish-Warning -text "$($errorEvents.Count) errors found in the application event log in the last $($pastSeconds ) seconds"
                  Publish-Text -text ($errorEvents | Select TimeCreated, ProviderName, Message | fl)
                }
                else
                {
                   Publish-Text -text "No errors found in the application event log in the last $($pastSeconds ) seconds"
                }

                #Write-Output $script:FailedRequest.Html
                                 
                # get the ReasonPhrase from the last line of the httperr.log                        
                $lastKnowProblem = [regex]::match($script:FailedRequest.Html,' 503 \d+ ([\w\/_]+) ').Groups[1].Value

                if ($ReasonPhrase.ContainsKey($lastKnowProblem))
                {
                    Publish-Text -text "Last known problem:"
                    Publish-Text -text $ReasonPhrase[$lastKnowProblem]
                }
                              
                if ($AppProcessmodel.identityType -eq "SpecificUser")
                {
                    Publish-Text -text "`r`nThe Application pool `'$($pool.Name)`' is running under account: `'$($AppProcessmodel.userName)`' "
                    Publish-Text -text "Is this account active, the password correct and not expired?"
                    Publish-Text -text "Output of `'net user $($AppProcessmodel.userName)`':`n"
                    & net user $AppProcessmodel.userName
                    Publish-Text -text "You may want to reset the password in the Advanced Settings for the application pool, in the `'Process Model Identity`' dialog."
                }
                # Write-Output ($AppProcessmodel | fl * |Out-String)
            }
            elseif ($fullStatus -eq "401.3")
            {
                If (Test-Path $potentialResource)
                {
                    Publish-Text -text "Here are the permissions for file: $potentialResource"
                    (Get-ACL $potentialResource).Access | Select IdentityReference, FileSystemRights, AccessControlType, IsInherited
                    # show the user running the pool
                    # suggest acl change to fix this problem
                    
                    if ($AppProcessmodel.identityType -eq "ApplicationPoolIdentity")
                    {
                        Publish-Text -text "`r`nThe Application pool is running under: `"IIS APPPOOL\$($pool.name)`""
                    }
                    else
                    {
                        Publish-Text -text "The Application pool is running under: $($AppProcessmodel.identityType)"
                    }   
                    
                    Publish-Text -text ""       
                    
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
            elseif ($fullStatus -match "40[143]\.503")
            {
                Publish-Text -text "The request was disallowed because of IP/Domain restrictions."
                
                $allowUnlisted = [bool](Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location "$($site.name)" -filter "system.webServer/security/ipSecurity" -name "allowUnlisted").Value          
                
                if (!($allowUnlisted))
                {
                    Publish-Warning -text "All unlisted addresses are NOT allowed"
                }
                $ipRe = (Get-WebConfiguration "system.webserver/security/ipsecurity/*" "IIS:\sites\$($site.name)" | Select ipAddress,subnetMask,domainName,allowed | ft -AutoSize | Out-String).Trim()

                if ($ipRe -ne $null)
                {
                    Publish-Text -text "Review these:"
                    Publish-Text -text $ipRe  
                }                        
                Publish-Text -text "Check both the site and the server level."                       

            }
            else
            {
                Publish-Text -text "It seems in this version we have no information about how to fix your problem, sorry."
                Publish-Verbose -Text "It seems in this version we have no information about how to fix your problem, sorry."
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
                    Publish-Text -text "Failed Request Tracing files are available:"
                    $frebFiles | ForEach {
                        Publish-Text -text $(Copy-FrebFiles $_.FullName)
                    }
                }
            }

            Exit Get-ExitCode -status $script:FailedRequest.Status -sub $script:FailedRequest.SubStatus
        }

    }

    Process
    {
        if ($OutputFile -ne "")
        {
            $outFolder = [System.IO.Path]::GetDirectoryName($OutputFile)
            if (!(Test-Path $outFolder))
            {
                Write-Warning "$outFolder doesn't exist, ouput file will not be created"
                $OutputFile = ""
            }
            else
            {
                # create an empty output file
                "" | Out-File $OutputFile
                Write-Host "Output is written to $OutputFile"
            }
        }
        
        Check-RequiredPrerequisites
        if ($install) {Install-OptionalTools}

        Import-Module WebAdministration -Verbose:$false 

        if ($ShowServer)
        {
            Show-ServerInfo
            Exit $ExitSuccess 
        }

        if ($ShowSite)
        {
            Show-Site -name $name
            Exit $ExitSuccess 
        }

        $site = Get-ChildItem iis:\sites\ | Where {$_.name -eq $name}

        if ($site -eq $null)
        {
            Publish-Warning -text "WebSite $name not found"
            Exit $WebSiteNotFound # Not Found
        }
        else
        {
            Show-TestSuccess -info "WebSite: `"$name`" exists"
        }

        if ($DisableFreb)
        {
            Disable-Tracing -siteId $site.id -siteName $site.Name
            Exit $ExitSuccess
        }

        if ($EnableFreb)
        {
            Enable-Tracing -siteId $site.id -siteName $site.Name -statuscodes "400-999" -resource "*"
            Exit $ExitSuccess
        }

        # Test WebSite is running
        if ($site.State -ne "Started")
        {
            Publish-Warning -text "WebSite $name is not running"
            Publish-Text -text "Please make sure the web site is running:"
            Show-PoshCommand "Start-WebSite `"$name`""
            Exit $WebSiteNotRunning
        }

        Show-TestSuccess -info "WebSite: `"$name`" is running"

        $poolName = $site.applicationPool

        $pool = Get-Item IIS:\\AppPools\$poolName

        # the following two tests are not really required because
        # if the pool wouldn't exist or running, the site wouldn't run either.
        if ($pool -eq $null)
        {
            Publish-Warning -text "Application Pool $poolName not found"
            Publish-Text -text "Make sure your website has a existing application pool assigned"
            Exit $AppPoolNotFound
        }
    
        if ($pool.State -ne "Started")
        {
            Publish-Warning -text "Application pool $poolName is not running"
            Publish-Text -text "Please make sure the Application pool is running:"
            Show-PoshCommand "Start-WebAppPool `"$poolName`""
            Exit $AppPoolNotRunning
        }
        
        $webRoot = [System.Environment]::ExpandEnvironmentVariables($site.PhysicalPath)

        Test-WebConfig -webRoot $webRoot

        $script:RequestStart = Get-Date
             
        $url = Get-Url -site $site -resource $Resource
        $status = Test-WebPage -url $url

        if ($status -eq 200)
        {
            Show-TestSuccess -info "The test request returned with status 200"
            Publish-SuccessText -text "All tests passed"
            Exit $WebSuccess
        }
        else
        {      
            Process-Page -site $site

            if (!($script:FailedRequest.Processed))
            {
                Process-LogEntry -site $site
            }

            if ($script:FailedRequest.Processed)
            {
                Process-Problem -webRoot $webRoot -pool $pool -site $site
            }
            else
            {
                Publish-FailureText "Request could not be processed, http status: $status"
            }
        }
    }

    End
    {
    }
