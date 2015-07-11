######################################################################################
# Integration Tests for Test-WebSite
# 
# These tests will make changes to your system, we are tyring to roll them back,
# but you never know. Best to run this on a throwaway VM.
# Run as an elevated administrator 
######################################################################################

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# create a unique name that we use for our temp files and folders
[string]$tempName = "Test-WebSite_" + (Get-Date).ToString("yyyyMMdd_HHmmss")

Describe "Test-WebSite" {

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
            & .\Test-WebSite.ps1 -Name Test1 -SkipPrerequisitesChecks -DontOfferFixes
        }  | should not throw

            $lastexitcode | should be 60015
        } 
                
        It 'WebSite not running' -test {
        {            
            New-Website -Name Test2 -PhysicalPath $env:temp -Port 10002 -id 10002| Stop-Website
            
            & .\Test-WebSite.ps1 -Name Test2 -SkipPrerequisitesChecks -DontOfferFixes
        }  | should not throw

            $lastexitcode | should be 60001
        } 

        It 'Web.Config missing' -test {
        {            
            $webRoot = Join-Path $tempFolder "test3"
            New-Item -Path $webRoot -ItemType Directory

            New-Website -Name Test3 -PhysicalPath $webRoot -Port 10003 -id 10003
            
            & .\Test-WebSite.ps1 -Name Test3 -SkipPrerequisitesChecks -DontOfferFixes
            }  | should not throw

            $lastexitcode | should be 60062
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
            
            & .\Test-WebSite.ps1 -Name Test4 -SkipPrerequisitesChecks -DontOfferFixes
             }  | should not throw

            $lastexitcode | should be 40314
        }
        
      It 'Basic Page okay' -test {
        {            
            $webRoot = Join-Path $tempFolder "test4"
            $homepage = Join-Path $webRoot "default.htm"
            "<html>Test page</html>" | Out-file $homepage
            Start-Sleep -Milliseconds 50
            
            & .\Test-WebSite.ps1 -Name Test4 -Resource "/default.htm" -SkipPrerequisitesChecks -DontOfferFixes
            }  | should not throw

            $lastexitcode | should be 20000
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
            
            & .\Test-WebSite.ps1 -Name Test5 -SkipPrerequisitesChecks -DontOfferFixes
             }  | should not throw

            $lastexitcode | should be 50019
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
     #   Start-Sleep -Seconds 20

        # roll back our changes
        Restore-WebConfiguration -Name $tempName
        Remove-WebConfigurationBackup -Name $tempName

        # remove the generated MoF files
   #     Get-ChildItem "$env:SystemDrive\inetpub\$tempName" | Remove-item -Recurse -Force
   #     Remove-item "$env:SystemDrive\inetpub\$tempName" -Force
    } 
}
