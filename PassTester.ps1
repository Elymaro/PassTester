#################################################################
#####                                                       #####
#####  Must be executed from a Domain Admin account         #####
#####                                                       #####
#####  Developped by Aurélien BOURDOIS                      #####
#####  https://www.linkedin.com/in/aurelien-bourdois/       #####
#################################################################

clear

Start-Transcript -Path "$env:USERPROFILE\Desktop\PassTester_log.txt" -Append | Out-Null

Write-Host " _____         _____ _____ _______ ______  _____ _______ ______ _____  "
Write-Host "|  __ \ /\    / ____/ ____|__   __|  ____|/ ____|__   __|  ____|  __ \ "
Write-Host "| |__) /  \  | (___| (___    | |  | |__  | (___    | |  | |__  | |__) |"
Write-Host "|  ___/ /\ \  \___ \\___ \   | |  |  __|  \___ \   | |  |  __| |  _  / "
Write-Host "| |  / ____ \ ____) |___) |  | |  | |____ ____) |  | |  | |____| | \ \ "
Write-Host "|_| /_/    \_\_____/_____/   |_|  |______|_____/   |_|  |______|_|  \_\`n"

if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "Must be opened from a Domain Admin account !"
    Stop-Transcript | Out-Null
    sleep 5
    exit
}

function date {
    (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

$directory_audit = "$env:USERPROFILE\Desktop\PassTester"
$directory_exports_NTDS = "$directory_audit\NTDS"

function NTDS_copy {
    if(Get-Module DSInternals)
    {
        Import-Module DSInternals
    }
    else
    {
        Install-Module -Name DSInternals
    }

    if (!$(Test-Path $directory_audit))
    {
        Write-Host "$(date) - Creating directories"
        New-Item -ItemType Directory -Path $directory_audit | Out-Null
    }

    if ($(Get-ChildItem $directory_audit) -ne $null)
    {
        Write-Host "$(date) - Folder $directory_audit is not empty !" -ForegroundColor Yellow
        Stop-Transcript | Out-Null
        Start-Sleep 5
        exit
    }
    else
    {
        New-Item -ItemType Directory -Path "$directory_audit\results" | Out-Null
        New-Item -ItemType Directory -Path "$directory_exports_NTDS" | Out-Null
    }

    #Copy of the NTDS database
    if ($env:LOGONSERVER.Substring(2) -ne $env:COMPUTERNAME)
    {
        #Creating a temporary share
        New-SmbShare -Path $directory_exports_NTDS -Name "Share_Audit" -FullAccess (Get-LocalGroup -SID "S-1-5-32-544").name

        $Partage = "\\$env:COMPUTERNAME\Share_Audit"
        #Log on to the DC
        $session = New-PSSession -ComputerName $env:LOGONSERVER.Substring(2) -Name Audit
        Write-Host "$(date) - Extracting NTDS database ..."
        #Remote copy of the NTDS database and transfer to the network share
        Invoke-Command -Session $session -ScriptBlock {
            param($Partage)
            NTDSUTIL "Activate Instance NTDS" "IFM" "Create Full $Partage" "q" "q"
        } -ArgumentList $Partage | Out-Null
        #Closing the network share
        Remove-SmbShare -Name "Share_Audit" -Force > $null
    }
    else
    {
        Write-Host "$(date) - Extracting NTDS database ..."
        NTDSUTIL "Activate Instance NTDS" "IFM" "Create Full $directory_exports_NTDS" "q" "q"# | Out-Null
    }

    Write-Host "$(date) - NTDS database decryption"
    #Loading the decryption key
    $Key = Get-BootKey -SystemHiveFilePath "$directory_exports_NTDS\registry\SYSTEM"

    #Decrypting the NTDS database with the SYSTEM key
    Get-ADDBAccount -BootKey $Key -DatabasePath "$directory_exports_NTDS\Active Directory\ntds.dit" -All |`
    Format-Custom -View HashcatNT | Out-File "$directory_audit\Hashdump.txt"

    #Deleting empty lines and krbtgt account and machines acounts
    $NTDS = Get-Content "$directory_audit\Hashdump.txt"
    $NTDS | Where-Object { $_ -ne '' -and $_ -notmatch "krbtgt" -and $_ -notmatch "\$" } | Get-Random -Count $NTDS.Count | Set-Content "$directory_audit\Hashdump_cleared.txt"
    
    Write-Host "$(date) - Extract Done !"
}

function Password_Control {
    if (!$(Test-Path "$directory_audit\Hashdump_cleared.txt"))
        {
            Write-Host "No file $directory_audit\Hashdump_cleared.txt present !"
            Sleep 10
            Exit
        }
    $NTDS = Get-Content "$directory_audit\Hashdump_cleared.txt"
    $total_users = $NTDS.count
    $compromised_count = 0
    $empty_count = 0
    #Users randomized to avoid to inject Administrator and Guest user in first
    $mixed_users = $NTDS | Get-Random -Count $NTDS.Count

    Write-Host "$(date) - Password control ..."

    ###### Tests HashNTLM #####

    # Display the progress bar
    $progressParams = @{
        Activity = "Processing in progress"
        Status   = "Loading ..."
        PercentComplete = 0
    }
    Write-Progress @progressParams
    $totalUsers = $NTDS.Count
    $i = 0

    # Control task
    foreach($user_key in $mixed_users)
    {   
        # Update the progress bar
        $progressParams.PercentComplete = ($i++ / $totalUsers) * 100
        $progressParams.Status = "$i / $totalUsers users"
        Write-Progress @progressParams

        if ($i -match "999")
        {Start-Sleep 600}

        $user = $user_key.split(":")[0]
        $hash = $user_key.split(":")[1]

        if($hash -like "31d6cfe0d16ae931b73c59d7e0c089c0" -or $hash -eq $null)
        {
            $user | Out-File "$directory_audit\results\Empty_users.txt" -Append
            Write-Host "[*]" -ForegroundColor Yellow -NoNewline; Write-Host " User's password " -NoNewline ; Write-Host "$user" -ForegroundColor Yellow -NoNewline; Write-Host " empty !"
            $empty_count ++
            continue
        }

        try {
            $request = Invoke-WebRequest "https://ntlm.pw/$hash" -UseBasicParsing | Select-Object StatusCode
        }
        catch {
            $request = $_.Exception
        }
        
        if ($request.StatusCode -eq "200")
        {
            $user | Out-File "$directory_audit\results\Compromised_users.txt" -Append
            Write-Host "[+]" -ForegroundColor Green -NoNewline; Write-Host " User's password " -NoNewline ; Write-Host "$user" -ForegroundColor Green -NoNewline; Write-Host " vulnerable !"
            $compromised_count ++ 
            #$request.content
        }
        elseif ($request.StatusCode -match "429")
        {
            Write "Too much request"
            Write-Host "Stopped at user : $user" -ForegroundColor Red
            Start-Sleep 600
        }
    }

    Write-Host "`n$(date) - Extract finished !"
    Write-Host "`n$i/$total_users users have been tested :"
    Write-Host "$empty_count empty passwords" -ForegroundColor Yellow
    Write-Host "$compromised_count compromised passwords" -ForegroundColor green
    Write-Host "Results available at $directory_audit\results\"
    Stop-Transcript | Out-Null
    Start-Sleep 60
}


Write-Host "Menu :"
Write-Host "1 - Only extract NTDS database"
Write-Host "2 - Only control NTLM hashes from a previous extract (to do from anonymous IP address)"
Write-Host "3 - Full (to do from anonymous IP address)"
Write-Host "4 - Exit"

$choice = Read-Host "Select an option"

Switch ($choice){
    "1" {NTDS_copy; Stop-Transcript | Out-Null}
    "2" {Password_Control}
    "3" {NTDS_copy; Password_Control}
    "4" {exit}
    "Default" {Write-Host "Invalid choice. Please choose a valid option."}
}
