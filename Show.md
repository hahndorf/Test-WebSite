# Using Show-WebSite.ps1

This script collects information about your IIS website which can be used to troubleshoot problems.

##Getting the script

There are several ways to get the script file to your computer, download the zip, clone the repository, save the content manually into a file, or run the following command in PowerShell:

	(New-Object net.WebClient).DownloadString('https://raw.githubusercontent.com/hahndorf/Test-WebSite/master/Show-WebSite.ps1') | out-file $env:userprofile\downloads\Show-WebSite.ps1 -force 

After downloading a PowerShell script from the Internet, you should always review it to make sure it doesn't do anything bad, especially because we have to run it as an elevated administrator. The script was saved to your downloads folder.

##Running the script

Open an elevated PowerShell and run:

    & $env:userprofile\downloads\Show-WebSite.ps1 "myWebSiteName"

To save the output into a file use:

    & $env:userprofile\downloads\Show-WebSite.ps1 "myWebSiteName" | Out-File "$env:userprofile\documents\myWebSiteName_info.txt"

If your web site is called 'Default Web Site' you don't have to specify the name.

If you want to include information about the IIS server, add the -iis switch:

    & $env:userprofile\downloads\Show-WebSite.ps1 -iis

Include the content of the output file in your support question:

    notepad "$env:userprofile\documents\myWebSiteName_info.txt"

More information can be found in the [main read.me](https://github.com/hahndorf/Test-WebSite)

##Problems running the script

You may get one of the following messages when trying to run the script:

### Execution Policy

    ...Show-WebSite.ps1 cannot be loaded because running scripts is disabled on this system...

PowerShell doesn't allow the execution of unsigned scripts, to
allow the execution of local unsigned scripts for this session run:

    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

To change the execution policy permanently, run:

	Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

### Windows Version

    WARNING: Your OS version is not supported

You need to have at least Windows 7 / Server 2008 R2 or newer to use this script.

### PowerShell Version

    WARNING: PowerShell version 2 or newer is required to run this script

Please install the latest version of PowerShell, 4 or even 5.

### WedAdministration Module

    WARNING: WebAdministration module is missing.

The script uses the PowerShell module WebAdministration, it comes with Windows but you need to enable it, run:

    dism.exe -online -enable-feature -featurename:IIS-ManagementScriptingTools

### Run as Administrator

    WARNING: "Please run this script as elevated administrator

To run this script you need to be an elevated administrator, run:

    Start-Process -Verb runas -FilePath $PSHOME\powershell.exe