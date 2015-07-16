######################################################################################
# Integration Tests for Test-WebSite.ps1
# 
# These tests will make changes to your system, we are tyring to roll them back,
# but you never know. Best to run this on a throwaway VM.
# It will restart IIS, so never use this on a production server
# Run as an elevated administrator 
######################################################################################

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# create a unique name that we use for our temp files and folders
[string]$tempName = "Test-WebSite_" + (Get-Date).ToString("yyyyMMdd_HHmmss")

Describe "Test-WebSite" {

    # exit codes
    [int]$ExitSuccess = 0
    [int]$WebSuccess = 20000
    [int]$ExitAccessDenied = 40100 
    [int]$OSVersionNotSupported = 60198 
    [int]$PowerShellVersionNotSupported = 60018 
    [int]$WebAdministrationModuleMissing = 60019 
    [int]$WebSiteNotFound = 60015 
    [int]$AppPoolNotFound = 60010 
    [int]$WebSiteNotRunning = 60001
    [int]$AppPoolNotRunning = 60011
    [int]$WebConfigMissing = 60062

    function Remove-WebRoot([string]$filePath)
    {
       if (Test-Path $filePath)
       {
           Get-ChildItem $filePath -Recurse | Remove-Item -Recurse
           Remove-Item $filePath
       }
    }

    try
    {
        # before doing our changes, create a backup of the current config        
        Backup-WebConfiguration -Name $tempName

        $tempFolder = Join-Path "$env:SystemDrive\inetpub" $tempName
        New-Item -Path $tempFolder -ItemType Directory

        It 'No WebSite' -test {
        {
            & .\Test-WebSite.ps1 -Name Test1 -DontOfferFixes
        }  | should not throw

            $lastexitcode | should be $WebSiteNotFound
        } 
                
        It 'WebSite not running' -test {
        {            
            New-Website -Name Test2 -PhysicalPath $env:temp -Port 10002 -id 10002| Stop-Website
            
            & .\Test-WebSite.ps1 -Name Test2 -DontOfferFixes
        }  | should not throw

            $lastexitcode | should be $WebSiteNotRunning
        } 

        It 'Web.Config missing' -test {
        {            
            $webRoot = Join-Path $tempFolder "test3"
            New-Item -Path $webRoot -ItemType Directory

            New-Website -Name Test3 -PhysicalPath $webRoot -Port 10003 -id 10003
            
            & .\Test-WebSite.ps1 -Name Test3 -DontOfferFixes -BeStrict
            }  | should not throw

            $lastexitcode | should be $WebConfigMissing
        }                    

        It 'EmptyWeb' -test {
        {            
            $webRoot = Join-Path $tempFolder "test4"
            New-Item -Path $webRoot -ItemType Directory
            $webConfig = Join-Path $webRoot "web.config"

        $webConfigTemplate = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
    </system.webServer>
</configuration>        
"@

            $webConfigTemplate | Set-Content $webConfig

            New-Website -Name Test4 -PhysicalPath $webRoot -Port 10004 -id 10004
            
            & .\Test-WebSite.ps1 -Name Test4 -DontOfferFixes
             }  | should not throw

            $lastexitcode | should be 40314 # should return a 403.14
        }
        
      It 'Basic Page okay' -test {
        {            
            $webRoot = Join-Path $tempFolder "test4"
            $homepage = Join-Path $webRoot "default.htm"
            "<html>Test page</html>" | Out-file $homepage
            Start-Sleep -Milliseconds 50
            
            & .\Test-WebSite.ps1 -Name Test4 -Resource "/default.htm" -DontOfferFixes
            }  | should not throw

            $lastexitcode | should be $WebSuccess
        }     
        
        
        It 'BrokenWebConfigXML' -test {
        {            
            $webRoot = Join-Path $tempFolder "test5"
            New-Item -Path $webRoot -ItemType Directory
            $webConfig = Join-Path $webRoot "web.config"

        $webConfigTemplate = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServerx>
    </system.webServer>
</configuration>        
"@

            $webConfigTemplate | Set-Content $webConfig

            New-Website -Name Test5 -PhysicalPath $webRoot -Port 10005 -id 10005
            
            & .\Test-WebSite.ps1 -Name Test5 -DontOfferFixes
             }  | should not throw

            $lastexitcode | should be 50019 # should return a 500.19
        }               

#        It 'Web1' -test {
#        {      

            # Cannot read configuration file due to insufficient permissions

#            $webRoot = Join-Path $tempFolder "test4"
#            $webConfig = Join-Path $webRoot "web.config"

#            & icacls.exe "$webConfig" /inheritance:d
#            & icacls.exe "$webConfig" /remove "BUILTIN\IIS_IUSRS"
#            & icacls.exe "$webConfig" /remove "IUSR"
#            & icacls.exe "$webConfig" /remove "everyone"
#            & icacls.exe "$webConfig" /remove "Users"
                                                    
#            & .\Test-WebSite.ps1 -Name Test4 -SkipPrerequisitesChecks -DontOfferFixes
#            }  | should not throw

#            $lastexitcode | should be 40314
#        }

    }
    finally
    {
        # enable sleep to see what happened to IIS before rolling back
        # uncomment this during debugging
        # Start-Sleep -Seconds 20
        
        Start-Sleep -Milliseconds 100

        # roll back our changes
        Restore-WebConfiguration -Name $tempName
        Remove-WebConfigurationBackup -Name $tempName

        Restart-Service was -Force

        # remove the generated MoF files
        Get-ChildItem "$env:SystemDrive\inetpub\$tempName" | Remove-item -Recurse -Force
        Get-ChildItem "$env:SystemDrive\inetpub\$tempName"  -Recurse | Remove-Item -Force -Recurse
        Remove-Item "$env:SystemDrive\inetpub\$tempName"
        # remove log files
        
        Get-ChildItem "$env:SystemDrive\inetpub\logs\LogFiles" | Where {$_.Name -match "^W3SVC1000"} | Remove-item -Recurse -Force
    } 
}
