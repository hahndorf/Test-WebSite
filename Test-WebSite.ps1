[CmdletBinding()]
[OutputType([int])]
param(
 [Parameter(Position=0)]
  [string]$Name = "Default Web Site"
)

    Begin
    {

        if(!(Get-Module -ListAvailable -Name WebAdministration))
        {
            Write-Warning  "Please ensure that WebAdministration module is installed."
            Exit 412 # Precondition failed.
        }

        $UserCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        $userIsAdmin = $false

        $UserCurrent.Groups | ForEach-Object { if($_.value -eq "S-1-5-32-544") {$userIsAdmin = $true} }

        if (!($userIsAdmin))
        {
            Write-Warning "Please run this script as elevated administrator"
            Exit 401 # Access denied.
        }

        Import-Module WebAdministration

        Function Show-TestSuccess([string]$info)
        {
            Write-Host "Test: $info " -ForegroundColor Green 
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

    }

    End
    {
    }



