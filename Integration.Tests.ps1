######################################################################################
# Integration Tests for Test-WebSite
# 
# There tests will make changes to your system, we are tyring to roll them back,
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

        It 'No WebSite' -test {
        {
            & .\Test-WebSite.ps1 -Name Test1 -SkipPrerequisitesChecks -DontOfferFixes
        }  | should not throw

            $lastexitcode | should be 404
        } 
                
        It 'WebSite not running' -test {
        {            
            New-Website -Name Test2 -PhysicalPath $env:temp -Port 10002 | Stop-Website
            
            & .\Test-WebSite.ps1 -Name Test2 -SkipPrerequisitesChecks -DontOfferFixes
        }  | should not throw

            $lastexitcode | should be 601
        } 
        
            
    }
    finally
    {
        # enable sleep to see what happened to IIS before rolling back
      #  Start-Sleep -Seconds 20

        # roll back our changes
        Restore-WebConfiguration -Name $tempName
        Remove-WebConfigurationBackup -Name $tempName

        # remove the generated MoF files
        Get-ChildItem $env:temp -Filter $tempName* | Remove-item -Recurse
    } 
}
