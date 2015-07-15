<#
.SYNOPSIS
    Shows information about an IIS Web server
.DESCRIPTION
    Creates a report about your server environment
    You can include this report when asking for help online.
    You may want to remove certain information from the report.
.PARAMETER Name
    The name of the web site to gather information for, as seen in IIS Manager or 'Get-WebSite'
.PARAMETER serverlevel
    If present, server level information will be included 
.EXAMPLE       
    Show-WebServer
    Shows information for the server
.EXAMPLE       
    Show-WebServer -modules | out-file $env:userprofile\Downloads\mysitereport.txt
    Shows information for the server including installed modules and saves it into a file
.NOTES
    Author: Peter Hahndorf
    Date:   July 15th, 2015    
#>

[CmdletBinding()]
[OutputType([int])]
param(
  [switch]$modules
)

    Begin
    {
        [int]$separatorWith = 70

        # a bunch of helper functions:
        Function Print-Attribute([string]$caption,[string]$value)
        {
            $caption = $caption + ":"
            $caption = $caption.PadRight(23," ")

            Write-Output "$caption $value" 
        }

        Function Print-Stuff($stuff)
        {
            Write-Output $stuff
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

        Function Show-ServerLevelInfo()
        {
            Print-SectionHeader "information about IIS:"

            Print-SubHeader "Installed IIS Components"

            # works in 6.2 and newer only
            # Get-WindowsOptionalFeature –Online | Where {$_.FeatureName -match "^IIS-" -and $_.State -eq "Enabled"} | Sort FeatureName | Select FeatureName | Format-Table -HideTableHeaders

            # the following works in Win7/2008R2 and newer           
            $tempFile = "$env:temp\TestWindowsFeature.log"
            & dism.exe /online /get-features /format:table | out-file $tempFile -Force       
            (Import-CSV -Delim '|' -Path $tempFile -Header Name,state | Where-Object {$_.Name.Trim() -match "^IIS-" -and $_.State.Trim() -eq "Enabled"} | Sort Name | Select Name | Format-Table -HideTableHeaders | Out-String).Trim()
            Remove-Item -Path $tempFile -Force

            Print-SubHeader "Global Modules"
            
            ((Get-WebConfiguration //globalmodules -PSPath "iis:\").collection | Sort-Object Name | Select Name | Format-Table -HideTableHeaders | Out-String).Trim()     
        }

        Function Show-MainObjects()
        {
            Print-SectionHeader "Web Sites:"
            (Get-ChildItem IIS:\Sites| Out-String).Trim()
            Print-SectionHeader "Application Pools:"
            (Get-ChildItem IIS:\AppPools | FT | Out-String).Trim()
            Print-SectionHeader "SSL Bindings:"
            (Get-ChildItem IIS:\SslBindings | Out-String).Trim()
            Print-SectionHeader "TLS Server Certificates: $((Get-ChildItem Cert:\LocalMachine\my | Where-Object {$_.EnhancedKeyUsageList -match "Server Authentication"}).Count)"
            
            netsh http show iplisten
        }

        Function Show-OSInfo()
        {
            Print-SubHeader "Show-WebServer output - $((Get-Date).ToString("d MMMM yyyy HH:mm:ss"))"

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

        $myOs = Get-WmiObject -Class Win32_OperatingSystem
#        $myOS = Get-CimInstance -ClassName Win32_OperatingSystem -Namespace root/cimv2

        if ([int]$myOS.BuildNumber -lt 7600)
        {   
            Write-Warning  "Your OS version is not supported" 
            Exit 60198 # Access denied.
        }

        if ([int]$PSVersionTable.PSVersion.Major -lt 2)
        {
            Write-Warning "PowerShell version 2 or newer is required to run this script"
            Exit 60018 # Access denied.
        }

        $UserCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userIsAdmin = $false
        $UserCurrent.Groups | ForEach-Object { if($_.value -eq "S-1-5-32-544") {$userIsAdmin = $true} }
        if (!($userIsAdmin))
        {
            Write-Warning "Please run this script as elevated administrator"
            Exit 40100 # Access denied.
        }

        if(!(Get-Module -ListAvailable -Name WebAdministration))
        { 
            Write-Warning "WebAdministration module is missing."
            Exit 41200 # Access denied.
        }

        Import-Module WebAdministration -Verbose:$false
    }
    Process
    {
        Show-OSInfo
        Show-MainObjects
        if ($modules) { Show-ServerLevelInfo }
    }
    End
    {
    }
