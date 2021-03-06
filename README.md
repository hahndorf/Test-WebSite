# Test-WebSite
A PowerShell script to test an IIS website for the most common setup problems.

### Installation and Usage

- [How to get, run and troubleshoot the script](Usage.md)

### Description

You should run this when you are having a problem with your site setup on IIS.
After checking a few things the script downloads a resource from your local site, if it doesn't return an http status of 200, it tries to find out more about the problem.
It also tries to suggest various things to fix the problem.

I often answer questions about IIS on [serverfault.com](http://serverfault.com), [stackoverflow.com](http://stackoverflow.com/) or [forums.iis.com](http://forums.iis.net/) and often people provide very little information about their problem.
Nearly always it would be helpful to know the sub-status code and people should try a few common troubleshooting things before asking a questions on these forums.

So if anybody could run this script before asking a question and providing the information it outputs, that would be very helpful for people answering questions.

I realized there are a lot of things this script could test and many ways in which it could break. So there is still a lot of work to do. So consider this a Beta.

The script can either just display information about the server (-ShowServer) or a web site (-ShowSite) but its primary function is to run some tests against a single web site.

The displayed information should be helpful for troubleshooting.

The purpose of this script is to allow people to fix their problems themselves and to create less support calls. So I wont do any support for IIS problems here.

### Requirements

- IIS 7.5+ (not all tested)
- Windows Server 2008 R2 (or Windows 7) with SP1 or newer. Nano Server is not supported.
- PowerShell 2 or higher
- PowerShell WebAdministration module installed.

This means the scripts run on Windows 7 SP1 without any additional downloads.
It may work on Server 2008, but you have to install PowerShell 2 and the IIS PowerShell module.

### Version History

- 0.6 - Back to a single file Test-WebSite.ps1
- 0.5 - Added Show-WebServer.ps1
- 0.4 - More features implemented
- 0.3 - Added Show-WebSite.ps1
- 0.2 - First working tests

### Tests

- Is the site running?
- Is the application pool running?
- Does a web.config file exists in the root?
- Does a request return a 200, if not what's the sub-status code?

### Future improvements

- Handle all kinds of 400 and 500 responses by providing more information.
- Actually executing the suggested fixes
- Configuring Failed Request tracing and analyzing the logs.

### Optional IIS components
- IIS logging with certain settings installed (use -install switch). This may be used to find the sub-status code of a response.
- IIS Failed request tracing installed (use -install switch). 

### Example output:

    .\Test-WebSite.ps1 -Resource /no.html

    Test: WebSite: "Default Web Site" exists
    Test: WebSite: "Default Web Site" is running
    Test: AppPool: "DefaultAppPool" is exists
    Test: AppPool: "DefaultAppPool" is running
    Test: Configuration "C:\inetpub\wwwroot\web.config" exists
    http://127.0.0.1/no.html - 401.3
    This HTTP status code indicates a problem in the NTFS file system permissions. This problem may occur even if the permi
    ssions are correct for the file that you are trying to access. For example, this problem occurs if the IUSR account doe
    s not have access to the C:\Winnt\System32\Inetsrv directory. For more information about how to resolve this problem, c
    heck the article in the Microsoft Knowledge Base: 942042

    Here are the permissions for file: C:\inetpub\wwwroot\no.html

    IdentityReference                                              FileSystemRights                       AccessControlType
    -----------------                                              ----------------                       -----------------
    NT AUTHORITY\SYSTEM                                                 FullControl                                   Allow
    BUILTIN\Administrators                                              FullControl                                   Allow
    NT SERVICE\TrustedInstaller                                         FullControl                                   Allow

    The Application pool is running under: "IIS APPPOOL\DefaultAppPool"

    You may want to give read access to IIS_IUSRS:
    & icacls.exe "C:\inetpub\wwwroot\no.html" /grant "BUILTIN\IIS_IUSRS:RX"
    This command has been copied to your clipboard

### Failed Request Tracing

There are a few pain points with Failed Request Tracing on IIS:

- You have to remember to install it.
- There are a lot of things to click when you set it up in IIS Manager and you have to remember to enable it for the site as well.
- When you navigate to `C:\inetpub\logs\FailedReqLogFiles` you are greeted with an UAC prompt because you don't have access to the folder. (Unless you run without UAC or a administrator user. I hope you don't).
- When double-clicking on an fr*.xml file, Internet Explorer opens and says `Content from this web site is blocked, blah blah blah about:internet`. When you click `close` all you get is some gobbly goop.

This script installs Failed Request Tracing and when using the -enableFreb switch, it configures it for the site and the failed http status. It gets rid of the `about:internet` prompt and copies the files to a location where standard users can read them.  

### Disclaimer

For now the code is pretty messy. I just throw things in to get some tests done.
I plan some major re-factoring later on.


