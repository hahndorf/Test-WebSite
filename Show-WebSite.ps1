<#
.SYNOPSIS
    Shows information about an IIS Web site
.DESCRIPTION
    Creates a report about your server environment
    You can include this report when asking for help online.
    You may want to remove certain information from the report.
.PARAMETER Name
    The name of the web site to gather information for, as seen in IIS Manager or 'Get-WebSite'
.PARAMETER serverlevel
    If present, server level information will be included 
.EXAMPLE       
    Show-WebSite
    Shows information for 'Default Web Site'
.EXAMPLE       
    Show-WebSite -Name MySite -serverlevel | out-file $env:userprofile\Downloads\mysitereport.txt
    Collects information for 'MySite' including server level data and saves it into a file
.NOTES
    Author: Peter Hahndorf
    Date:   July 5th, 2015    
#>

[CmdletBinding()]
[OutputType([int])]
param(
 [Parameter(Position=0)]
  [string]$Name = "Default Web Site",
  [alias("iis")]
  [alias("server")]
  [switch]$serverlevel
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

        Function Show-SiteInfo($site,$pool)
        {
            Print-SubHeader "Show-WebSite output - $((Get-Date).ToString("d MMMM yyyy HH:mm:ss"))"

            Print-SectionHeader "Operating System:"

            $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
          #  $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Namespace root/cimv2
            $webRoot = [System.Environment]::ExpandEnvironmentVariables($site.PhysicalPath)

            Print-Attribute "Caption" $($OSInfo.Caption)
            Print-Attribute "Version" $($OSInfo.Version)
            Print-Attribute "SystemDirectory" $($OSInfo.SystemDirectory)
            Print-Attribute "OSArchitecture" $($OSInfo.OSArchitecture)
            Print-Attribute "MUILanguages" $($OSInfo.MUILanguages)             

            Print-SectionHeader "Web Site"

            Print-Attribute "Name" $($site.name)
            Print-Attribute "PhysicalPath" $webRoot         
            
            Print-SubHeader "Bindings"

            (($site | Select -expandproperty bindings).collection | format-table -AutoSize | Out-String).Trim()
            
            $limits = ($site | Select -expandproperty limits).collection
            if ($limits.count -gt 0)
            {
                Print-SubHeader "Limits"
                ($limits |format-table -AutoSize | Out-String).Trim()
            }

            Print-SubHeader "Default Documents"
            (Get-WebConfiguration "system.webserver/defaultdocument/files/*" "IIS:\sites\$($site.Name)" | Select value | Format-Table -HideTableHeaders  | Out-String).Trim()

            Print-SubHeader "Error Pages"
            (Get-WebConfiguration "system.webserver/httpErrors" "IIS:\sites\$($site.name)" | Format-Table -Property ErrorMode,existingResponse,defaultResponseMode  -AutoSize | Out-String).Trim()

            Print-SubHeader "Authentication"
            Get-WebConfiguration "system.webserver/security/authentication/*" "IIS:\sites\$($site.Name)" | Sort-Object SectionPath | foreach{
                 Write-Output ""
                 $($_.SectionPath -replace "/system.webServer/security/authentication/","")
                 Write-Output ""
                 ($_ | select -expandproperty attributes | Where {$_.Name -ne "password"} | Select Name,Value | Format-Table -AutoSize | out-string).Trim()
            }

            Show-PoolInfo $pool

            Print-SectionHeader "NTFS permissions"

            Print-SubHeader "Folder permissions for $webRoot"

            ((Get-ACL $webRoot).Access | Sort-Object IdentityReference | Select IdentityReference, FileSystemRights, AccessControlType, IsInherited | Format-Table -AutoSize | out-string).Trim()

            $virDirs = Get-WebVirtualDirectory -site "$($site.name)"

            if ($virDirs.count -gt 0)
            {
                Print-SectionHeader "Virtual Directories"
                ($virDirs | Format-Table -Property Path,PhysicalPath,AllowSubDirConfig,UserName  -AutoSize | Out-String).Trim()
            }

            $apps = Get-WebApplication -site "$($site.name)"
            
            if ($apps.count -gt 0)
            {
                Print-SectionHeader "Applications"
                ($apps | Select Path,PhysicalPath,applicationPool | Format-Table -AutoSize | Out-String).Trim()
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
        $site = Get-ChildItem iis:\sites\ | Where {$_.name -eq "$name"}
        if ($site -eq $null)
        {
            Write-Warning "The WebSite `'$name`' could not found"

            Write-Host "Existing sites on this server:"
            Get-ChildItem iis:\sites | Select Name | Format-Table -HideTableHeaders -AutoSize

            Exit 60015 # Not Found
        }

        $poolName = $site.applicationPool
        $pool = Get-Item "IIS:\\AppPools\$poolName"

        if ($pool -eq $null)
        {
            Write-Warning "Application Pool $poolName not found"
            Write-Output "Make sure your website has a existing application pool assigned"
            Exit 60010
        }

        Show-SiteInfo -site $site -pool $pool    
        if ($serverlevel)
        {
            Show-ServerLevelInfo
        }   
    }
    End
    {
    }
