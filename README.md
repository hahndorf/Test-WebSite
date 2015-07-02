# Test-WebSite
A PowerShell script to test an IIS website for the most common setup problems.

### Description

You should run this when you are having a problem with your site setup on IIS.
After checking a few things the script calls a page on your site, if not a http status of 200, it checks the IIS logs for that request to get the substatus code.
It then tries to suggest various things to fix the problem.

### Requirements

- IIS 8.5 (any IIS 7+ may work, not tested)
- PowerShell 3 or higher
- PowerShell WebAdministration module installed.
- Windows Server 2012 R2 (others may work)
- IIS logging with certain settings installed
- IIS Failed request tracing installed

### Version

0.2 - First tests

### Tests

- Is the site running
- Is the application pool running
- Does a web.config file exists in the root
- Does a request return a 200, if not what's the substatus code?

### Future improvements

- Actually executing the suggested fixes
- Handle all kind of 400 and 500 responses
- Configuring Failed Request tracing and analyzing the logs.

### Installation

Just copy the Test-WebSite.ps1 file and run it elevated on your IIS box.

### Example output:

    ^D:\: .\Test-WebSite.ps1 -Resource /no.html -skip

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

### Disclaimer

For now the code is pretty messy. I just throw things in to get some tests done.
I plan some major re-factoring later on.