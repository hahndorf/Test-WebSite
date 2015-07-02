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
.PARAMETER SkipPrerequisitesChecks
    If specified, several checks for prerequisites are not performed. Because these cecks may take
    some time you can choose to skip them if you are sure you have them.
.EXAMPLE       
    Test-WebSite -Name MySite
    Uses the default tests against the web site named 'MySite'
.EXAMPLE       
    Test-WebSite -Resource "/login.asp?user=foo" -SkipPrerequisitesChecks
    Uses the default tests against the specified resource on the web site named 'Default Web Site'. Skips checks.
.NOTES
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
  [alias("skip")]
  [switch]$SkipPrerequisitesChecks
)

    Begin
    {
        $UserCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userIsAdmin = $false
        $UserCurrent.Groups | ForEach-Object { if($_.value -eq "S-1-5-32-544") {$userIsAdmin = $true} }

        $statusInfo = New-Object 'System.Collections.Generic.dictionary[string,string]'
        $statusInfo.Add("404.0","The file that you are trying to access does not exist")
        $statusInfo.Add("401.3","This HTTP status code indicates a problem in the NTFS file system permissions. This problem may occur even if the permissions are correct for the file that you are trying to access. For example, this problem occurs if the IUSR account does not have access to the C:\Winnt\System32\Inetsrv directory. For more information about how to resolve this problem, check the article in the Microsoft Knowledge Base: 942042 ")

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

        if (!($SkipPrerequisitesChecks))
        {
            Write-Output "Checking prerequisites..."

            if (!($userIsAdmin))
            {
                Write-Warning "Please run this script as elevated administrator"
                Show-PoshCommand "Start-Process -Verb runas -FilePath $PSHOME\powershell.exe"
                Exit 401 # Access denied.
            }

            if(!(Get-Module -ListAvailable -Name WebAdministration))
            {
                Write-Warning  "Please ensure that WebAdministration module is installed."
                Show-PoshCommand "Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementScriptingTools"
                Exit 412 # Precondition failed.
            }

            if ((Get-WindowsOptionalFeature –Online | Where {$_.FeatureName -eq "IIS-HttpLogging" -and $_.State -eq "Enabled"}).count -eq 0) 
            {
                Write-Warning  "Please ensure that IIS-HttpLogging is installed."
                Show-PoshCommand "Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging"
                Exit 412 # Precondition failed.            
            }

            if ((Get-WindowsOptionalFeature –Online | Where {$_.FeatureName -eq "IIS-HttpTracing" -and $_.State -eq "Enabled"}).count -eq 0) 
            {
                Write-Warning  "Please ensure that IIS-HttpTracing is installed."
                Show-PoshCommand "Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing"
                Exit 412 # Precondition failed.            
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

        Function Process-Problem([string]$webRoot,[string]$url,[int]$status,[int]$subStatus,$pool,$site)
        {
            $fullStatus = "$status.$subStatus"
            Write-Warning "$url - $fullStatus"
            Write-Warning $statusInfo[$fullStatus]

            $res = $url -replace "^https?://[^/]+", ""
            $res = $res -replace "/","\"
            $potentialResource = Join-Path $webRoot $res

             Write-Output ""

            $AppProcessmodel = ($pool | Select -ExpandProperty processmodel)
            $webRoot = [System.Environment]::ExpandEnvironmentVariables($site.PhysicalPath)

            if ($fullStatus -eq "401.3")
            {
                If (Test-Path $potentialResource)
                {
                    Write-Output "Here are the permissions for file: $potentialResource"
                    (Get-ACL $potentialResource).Access | Select IdentityReference, FileSystemRights, AccessControlType
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
                        Show-PoshCommand -info "& icacls.exe `"$potentialResource`" /grant `"BUILTIN\IIS_IUSRS:RX`" " "You may want to give read access to IIS_IUSRS"
                    }  
                    else
                    {                        
                        Show-PoshCommand -info "& icacls.exe `"$potentialResource`" /grant `"IUSR:RX`" " "You may want to give read access to IUSR"
                        Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location `'$($site.Name)`' -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'userName' -value ''" "Or use the ApplicationPoolIdentity as user for anonymous access" 
                    }                                        
                }
            }
        }
    }
    Process
    {

        $site = (Get-Item "IIS:\sites\$name")

        if ($site -eq $null)
        {
            Write-Warning "WebSite $name not found"
            Exit 404 # Not Found
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
            Exit 601
        }

        Show-TestSuccess -info "WebSite: `"$name`" is running"

        $poolName = $site.applicationPool

        $pool = Get-Item IIS:\\AppPools\$poolName



        if ($pool -eq $null)
        {
            Write-Warning "Application Pool $poolName not found"
            Write-Output "Make sure your website has a existing application pool assigned"
            Exit 610
        }

        Show-TestSuccess -info "AppPool: `"$poolName`" is exists"
    
        if ($pool.State -ne "Started")
        {
            Write-Warning "Application pool $poolName is not running"
            Write-Output "Please make sure the Application pool is running:"
            Show-PoshCommand "Start-WebAppPool `"$poolName`""
            Exit 611
        }

        Show-TestSuccess -info "AppPool: `"$poolName`" is running"
        
        $webRoot = [System.Environment]::ExpandEnvironmentVariables($site.PhysicalPath)

        $webConfig = Join-Path $webRoot "web.config"

        if (!(Test-path $webConfig))
        {
            Write-Warning "Web.Config file does not exists in web root"
            Write-Output "Please make sure $webConfig exists."
            Exit 662
        }

        Show-TestSuccess -info "Configuration `"$webConfig`" exists"

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
                Exit 664            
            }

            if ($logfile.logExtFileFlags -notMatch "HttpSubStatus")
            {
                Write-Warning "Please include the sc-substatus field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",HttpSubStatus"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                Exit 665            
            }

            if ($logfile.logExtFileFlags -notMatch "UserAgent")
            {
                Write-Warning "Please include the UserAgent field in your logs"         
            
                $logFields = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter $filter -name "logExtFileFlags").ToString()               
                $logFields += ",UserAgent"

                $logFields = "'" + $logFields + "'"

                Show-PoshCommand -info "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter $filter -name 'logExtFileFlags' -value $logFields"
                Exit 666            
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
                        $cols = $row.Split(" ") 

                        Process-Problem $webRoot $($request.Value) $($cols[$statusColumn-1]) $($cols[$subStatusColumn-1])  $pool $site                                     
                    }
                } # foreach row
            } # for each request
        } # end if requests
    } # end process

    End
    {
    }
