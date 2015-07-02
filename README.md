# Test-WebSite
A PowerShell script to test an IIS website for the most common setup problems.

### Requirements

- IIS 7 or higher
- PowerShell 3 or higher
- PowerShell WebAdministration module installed.
- Windows Server 2012 R2 (others may work)

### Version

0.1 - initial empty script

### Tests

- Is the site running
- Is the application pool running
- Does a web.config file exists in the root
- Does a request return a 200, if not what's the substatus code?

### Planned tests

- Correct NTFS permissions 
- Handle various 404.x responses

### Installation

Just copy the Test-WebSite.ps1 file and run it elevated on your IIS box.