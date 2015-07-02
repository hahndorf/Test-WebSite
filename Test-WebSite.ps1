[CmdletBinding()]
[OutputType([int])]
param(
 [Parameter(Position=0)]
  [string]$Name = "Default Web Site",
  [alias("skip")]
  [switch]$SkipPrerequisitesChecks
)

    Begin
    {
        $UserCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userIsAdmin = $false
        $UserCurrent.Groups | ForEach-Object { if($_.value -eq "S-1-5-32-544") {$userIsAdmin = $true} }

        if (!($SkipPrerequisitesChecks))
        {
            if (!($userIsAdmin))
            {
                Write-Warning "Please run this script as elevated administrator"
                Write-Output "Start-Process -Verb runas -FilePath $PSHOME\powershell.exe"
                Exit 401 # Access denied.
            }

            if(!(Get-Module -ListAvailable -Name WebAdministration))
            {
                Write-Warning  "Please ensure that WebAdministration module is installed."
                Write-Output "Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementScriptingTools"
                Exit 412 # Precondition failed.
            }

            if ((Get-WindowsOptionalFeature –Online | Where {$_.FeatureName -eq "IIS-HttpLogging" -and $_.State -eq "Enabled"}).count -eq 0) 
            {
                Write-Warning  "Please ensure that IIS-HttpLogging is installed."
                Write-Output "Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging"
                Exit 412 # Precondition failed.            
            }

            if ((Get-WindowsOptionalFeature –Online | Where {$_.FeatureName -eq "IIS-HttpTracing" -and $_.State -eq "Enabled"}).count -eq 0) 
            {
                Write-Warning  "Please ensure that IIS-HttpTracing is installed."
                Write-Output "Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing"
                Exit 412 # Precondition failed.            
            }
        }

        $userAgentRoot = "Test-WebSite"

        Import-Module WebAdministration -Verbose:$false
        
        Function Show-TestSuccess([string]$info)
        {
            Write-Host "Test: $info " -ForegroundColor Green 
        }

        Function Show-PoshCommand([string]$info)
        {
            Write-Host "You may use the following command:"
            Write-Host $info -ForegroundColor Black -BackgroundColor Gray
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
            Write-Output "Start-WebSite `"$name`""
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
            Write-Output "Start-WebAppPool `"$poolName`""
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

        $requests = New-Object 'System.Collections.Generic.dictionary[int64,string]'

        foreach($binding in $site.Bindings.collection)
        {
            # ignore non-http protocols
            if ($binding.protocol -match "^http")
            {
                $url = Convert-Binding -binding $binding
                $ticks = [System.DateTime]::Now.Ticks
               
                $status = Test-WebPage -url $url -ticks $ticks

                $requests.Add($ticks,$url)            
            }

        }

        # flush logbuffer to see log entries right away
        & netsh http flush logbuffer | Out-Null

        $logfile = $site.logfile | Select -ExcludeProperty Logfile

      #  $logfile 


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
        
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Default Web Site']/logFile" -name "logExtFileFlags" -value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,TimeTaken,ServerPort,UserAgent,Referer,HttpSubStatus"



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

        foreach($request in $requests.GetEnumerator())
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
                    Write-OutPut "$($request.Value) - $($cols[$statusColumn-1]).$($cols[$subStatusColumn-1])"                                        
                }
            }

        }
    }

    End
    {
    }
