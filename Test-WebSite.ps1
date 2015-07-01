[CmdletBinding()]
[OutputType([int])]
param(
 [Parameter(Position=0)]
  [string]$Name = "Default Web Site"
)

    Begin
    {

        if(!(Get-Module -ListAvailable -Name WebAdministration))
        {
            Write-Warning  "Please ensure that WebAdministration module is installed."
            Exit 412 # Precondition failed.
        }

        $UserCurrent = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        $userIsAdmin = $false

        $UserCurrent.Groups | ForEach-Object { if($_.value -eq "S-1-5-32-544") {$userIsAdmin = $true} }

        if (!($userIsAdmin))
        {
            Write-Warning "Please run this script as elevated administrator"
            Exit 401 # Access denied.
        }

        Import-Module WebAdministration
    }
    Process
    {

        $site = (Get-Item IIS:\sites\$name)

        if ($site -eq $null)
        {
            Write-Warning "WebSite $name not found"
            Exit 404 # Not Found
        }
        else
        {
            $site
        }

    }
    End
    {
    }



