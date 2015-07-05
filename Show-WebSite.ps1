<#
.SYNOPSIS
    Shows information about your IIS Web site
.DESCRIPTION
    Creates a report about your server environment is created in C:\inetpub\TestWebSiteTempData
    You can include this report when asking for help online.
    You may want to remove certain information from that report.
.PARAMETER Name
    The name of the web site to test, as seen in IIS Manager or 'Get-WebSite'
.PARAMETER serverlevel
    If present, server level information will be included 
.EXAMPLE       
    Test-WebSite -Name MySite
    Shows information for 'MySite'
.NOTES
    Author: Peter Hahndorf
    Date:   July 5th, 2015    
#>

[CmdletBinding()]
[OutputType([int])]
param(
 [Parameter(Position=0)]
  [string]$Name = "Default Web Site",
  [alias("server,iis")]
  [switch]$serverlevel
)

    Begin
    {
        [int]$separatorWith = 70

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

            Get-WindowsOptionalFeature –Online | Where {$_.FeatureName -match "^IIS-" -and $_.State -eq "Enabled"} | Sort FeatureName | Select FeatureName | Format-Table -HideTableHeaders

            Print-SubHeader "Global Modules"
            
            (Get-WebConfiguration //globalmodules -PSPath "iis:\").collection | Sort-Object Name | Select Name | Format-Table -HideTableHeaders      
        }

        Function Show-SiteInfo($site,$pool)
        {
            Print-SubHeader "Show-WebSite output - $((Get-Date).ToString("d MMMM yyyy HH:mm:ss"))"

            Print-SectionHeader "Operating System:"

            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Namespace root/cimv2
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

            ($site | Select -expandproperty bindings).collection | format-table -AutoSize

            Print-SubHeader "Limits"

            ($site | Select -expandproperty limits).collection |format-table -AutoSize

            Print-SubHeader "Default Documents"
            Get-WebConfiguration "system.webserver/defaultdocument/files/*" "IIS:\sites\$($site.Name)" | Select value | Format-Table -HideTableHeaders

            Print-SubHeader "Authentication"
            Get-WebConfiguration "system.webserver/security/authentication/*" "IIS:\sites\test" | Sort-Object SectionPath | foreach{
                $($_.SectionPath -replace "/system.webServer/security/authentication/","")
                 $_ | select -expandproperty attributes | Where Name -ne "password" | Select Name,Value | Format-Table -AutoSize
            }

            Show-PoolInfo $pool

            Print-SectionHeader "NTFS permissions"

            Print-SubHeader "Folder permissions for $webRoot"

            (Get-ACL $webRoot).Access | Sort-Object IdentityReference | Select IdentityReference, FileSystemRights, AccessControlType, IsInherited

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
            Write-Output "WebAdministration module is missing."
            Exit 41200 # Access denied.
        }

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

        $poolName = $site.applicationPool
        $pool = Get-Item IIS:\\AppPools\$poolName

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
