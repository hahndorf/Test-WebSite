# Using Test-WebSite.ps1

##Getting the script

There are several ways to get the script file to your computer, download the zip, clone the repository, save the content manually into a file. 
You can also get it with PowerShell:

Open an elevated PowerShell window, first cd into a directory of your choice to store the script in, e.g.:

	cd ~\Downloads

then download the script:

	(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/hahndorf/Test-WebSite/master/Test-WebSite.ps1') | out-file .\Test-WebSite.ps1 -force 

After downloading a PowerShell script from the Internet, you should always review it to make sure it doesn't do anything bad, especially because we have to run it as an elevated administrator. 

##Running the script

Assuming you are still in the location you downloaded the script to, find out more about the parameters you can use for the script:

    help .\Test-WebSite.ps1 -full

The most common use cases are:

### Show server information

    .\Test-WebSite.ps1 -ShowServer

### Show site information
	.\Test-WebSite.ps1 -ShowSite -Name siteName

### Test a web site
	.\Test-WebSite.ps1 -Name siteName

To save the output into a file use:

    .\Test-WebSite.ps1 -Name siteName | Out-File "~\documents\info.txt"

To include the content of the output file in your support question, first run

    notepad "~\documents\info.txt"

then review the text and remove anything you don't want to share with the support community. Use the rest as part of your support request.

More information can be found in the [main read.me](https://github.com/hahndorf/Test-WebSite)

##Problems running the script

You may get one of the following messages when trying to run a script:

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

The scripts are using the PowerShell module WebAdministration, it comes with Windows but you need to enable it, run:

    dism.exe -online -enable-feature -featurename:IIS-ManagementScriptingTools

### Run as Administrator

    WARNING: "Please run this script as elevated administrator

To run this script you need to be an elevated administrator, run:

    Start-Process -Verb runas -FilePath $PSHOME\powershell.exe