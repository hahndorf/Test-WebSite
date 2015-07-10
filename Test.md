# Using Test-WebSite.ps1

This script helps you troubleshooting problems with your IIS website.

##Getting the script

There are several ways to get the script file to your computer, download the zip, clone the repository, save the content manually into a file, or run the following command in PowerShell:

	(new-object net.webclient).DownloadString('https://raw.githubusercontent.com/hahndorf/Test-WebSite/master/Test-WebSite.ps1') | out-file $env:userprofile\downloads\Test-WebSite.ps1 -force 

After downloading a PowerShell script from the Internet, you should always review it to make sure it doesn't do anything bad, especially because we have to run it as an elevated administrator.

##Running the script

Open an elevated PowerShell and run:

    & $env:userprofile\downloads\Test-WebSite.ps1 "myWebSiteName"

To save the output into a file use:

    & $env:userprofile\downloads\Test-WebSite.ps1 "myWebSiteName" | Out-File "$env:userprofile\documents\myWebSiteName_Tests.txt"

If you web site is called 'Default Web Site' you don't have to specify the name.

Add the content of the output file to you support question:

    notepad "$env:userprofile\documents\myWebSiteName_Tests.txt"

More information can be found in the [main read.me](https://github.com/hahndorf/Test-WebSite)