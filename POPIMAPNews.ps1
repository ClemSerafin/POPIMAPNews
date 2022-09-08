<#

.DESCRIPTION
This script will send a mail with the list of POP IMAP Users

.EXAMPLE
./POPIMAPNews.ps1

.INPUTS
Ini File

.OUTPUTS
CSV File

.NOTES
	===========================================================================
    NAME    : POPIMAPNews.ps1
    VERSION : 0.1
    AUTHOR  : Clément SERAFIN
    DATE    : 06/09/2022
    USAGE   : .\POPIMAPNews.ps1
    COMMENTS:     
	===========================================================================

.LINK
http://msblog.fr

#>


# ---------------------------
# Logs management function
# ---------------------------

Function Log-Start {
    <#
    .DESCRIPTION
      CrÃ©e un log file avec le path et nom qu'on lui passe en paramÃ¨tre. Check si le log file existe et le supprime pour en crÃ©er un nouveau.
      Une fois le log file crÃ©Ã©, Ã©crit dedans les donnÃ©es initiales
  
    .PARAMETER LogPath
      Mandatory. Path de crÃ©ation du log. Exemple: C:\Windows\Temp
  
    .PARAMETER LogName
      Mandatory. Nom du log file Ã  crÃ©er. Exemple: Test_Script.log
        
    .PARAMETER ScriptVersion
      Mandatory. Version du script Ã  Ã©crire dans le log. Example: 1.0
  
    .OUTPUTS
      Log file crÃ©Ã©
  
    .EXAMPLE
      Log-Start -LogPath "C:\Windows\Temp" -LogName "Test_Script.log" -ScriptVersion "1.5"
    #>
      
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$LogName, [Parameter(Mandatory=$true)][string]$ScriptVersion)
    
    Process{
      $sFullPath = $LogPath + "\" + $LogName
      
      #Check if file exists and delete if it does
      #If((Test-Path -Path $sFullPath)){
      #  Remove-Item -Path $sFullPath -Force
      #}
      
      #Create file and start logging
      #New-Item -Path $LogPath -Value $LogName -ItemType File
      Out-File -FilePath $sFullPath -encoding utf8 -Append
      
      Add-Content -Path $sFullPath -Value "***************************************************************************************************"
      Add-Content -Path $sFullPath -Value "Started processing at [$([DateTime]::Now)]."
      Add-Content -Path $sFullPath -Value "***************************************************************************************************"
      Add-Content -Path $sFullPath -Value ""
      Add-Content -Path $sFullPath -Value "Running script version [$ScriptVersion]."
      Add-Content -Path $sFullPath -Value ""
      Add-Content -Path $sFullPath -Value "***************************************************************************************************"
      Add-Content -Path $sFullPath -Value ""
    
      #Write to screen for debug mode
      Write-Debug "***************************************************************************************************"
      Write-Debug "Started processing at [$([DateTime]::Now)]."
      Write-Debug "***************************************************************************************************"
      Write-Debug ""
      Write-Debug "Running script version [$ScriptVersion]."
      Write-Debug ""
      Write-Debug "***************************************************************************************************"
      Write-Debug ""
    }
  }
  Function Log-Finish {
    <#
    .DESCRIPTION
      Ecrit les logs avec les donnÃ©s de fin et exit le script
    
    .PARAMETER LogPath
      Mandatory. Full path du log file sur lequel on veut Ã©crire les donnÃ©s de fin
  
    .PARAMETER NoExit
      Optional. Si ce paramÃ¨tre est Ã  True, la fonction ne va pas exit le script
  
    .EXAMPLE
      Log-Finish -LogPath "C:\Windows\Temp\Test_Script.log"
  
    .EXAMPLE
      Log-Finish -LogPath "C:\Windows\Temp\Test_Script.log" -NoExit $True
    #>
    
    [CmdletBinding()]
    
    Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$false)][string]$NoExit)
    
    Process{
      Add-Content -Path $LogPath -Value ""
      Add-Content -Path $LogPath -Value "***************************************************************************************************"
      Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
      Add-Content -Path $LogPath -Value "***************************************************************************************************"
    
      #Write to screen for debug mode
      Write-Debug ""
      Write-Debug "***************************************************************************************************"
      Write-Debug "Finished processing at [$([DateTime]::Now)]."
      Write-Debug "***************************************************************************************************"
    
      #Exit calling script if NoExit has not been specified or is set to False
      If(!($NoExit) -or ($NoExit -eq $False)){
        Exit
      }    
    }
  }
  
  Function Write-Log {
      <#
    .DESCRIPTION
      Ecrit une ligne dans le fichier de logs
    
    .PARAMETER DBG
      Optional. PlacÃ© Ã  la fin de la ligne de log il signale une INFORMATION
  
    .PARAMETER SCS
      Optional. PlacÃ© Ã  la fin de la ligne de log il signale un SUCCESSFUL
  
    .PARAMETER WAR
      Optional. PlacÃ© Ã  la fin de la ligne de log il signale un WARNING
  
    .PARAMETER ERR
      Optional. PlacÃ© Ã  la fin de la ligne de log il signale une ERREUR
  
    .EXAMPLE
     Write-Log  " > Pikachu is the best" "DBG"
     Write-Log  " > Pikachu vient de lancer fatal-foudre" "SCS"
     Write-Log  " > Pikachu est en surtension" "WAR"
     Write-Log  " > Pikachu a Ã©chouÃ© Ã  lancer vive-attaque" "ERR"
    #>
    
      Param (
          [String] $Value = '',
          [ValidateSet('   ','WAR','ERR','SCS','DBG')]
          [String] $Type  = '   ',
          [Switch] $NoNewLine,
          [Switch] $Status
      )
  
      $l_ColorFG = @{'   ' = 'White';
                   'WAR' = 'Yellow';
                   'ERR' = 'Red';
                   'SCS' = 'Green';
                   'DBG' = 'Cyan'}
  
      If($Type -ne '   ' -and $Type -ne 'WAR' -and $Type -ne 'ERR' -and $Type -ne 'SCS' -and $Type -ne 'DBG') {
          $Type  = '   '
      }
  
      If($Type -eq 'WAR') {$g_Warnings++} ElseIf($Type -eq 'ERR') {$g_Errors++;$stack=$($_.ScriptStackTrace)}
  
      If($c_CreateLogFile) {
          If(!(Test-Path -Path $c_LogPath)) {
              New-Item -Path $c_LogPath -ItemType File -Force | Out-Null
          }
          
          if ($Status)
          {
              Add-Content -Path $c_LogPath -Value ('{0} {1}' -f $Type, $Value) -encoding UTF8
          }
          Else
          {
              Add-Content -Path $c_LogPath -Value ('{0} {1} {2}' -f (Get-Date -UFormat '%Y/%m/%d %H:%M:%S'), $Type, $Value) -encoding UTF8 -NoNewline:$NoNewLine
          }
      }
  
      if ($Status)
      {
          Write-Host ('{0} {1} {2}' -f $Type, $Value , $stack) -ForegroundColor $l_ColorFG[$Type]
      }
      Else
      {
          Write-Host ('{0} {1} {2}' -f (Get-Date -UFormat '%Y/%m/%d %H:%M:%S'), $Type, $Value) -ForegroundColor $l_ColorFG[$Type] -NoNewline:$NoNewLine
      }
  }
  
  Function Start-Script {
  <# 
    .Description 
      Initie le script avec la vÃ©rification des paramÃ¨tres PS ou du RunAsAdmin
  
    .PARAMETER DisplayParameter
      Optional. Affiche les paramÃ¨tres trouvÃ©s par la fonction dans le log
  
    .PARAMETER Color
      Optional. Initie la couleur dÃ©clarÃ© dans la fonction pour la console PS
  
    .Example
      C:\PS>Start-Script -DisplayParameter -Color
  #>  
      Param (
          [switch] $DisplayParameter,
          [switch] $Color
      )
  
      #Backgroup color configuration
      if ($color) {
          $HOST.UI.RawUI.BackgroundColor = "DarkBlue"
          Clear-Host
      }
  
      Write-Log '###--------------------------------------------------------------------------------'
      Write-Log "# Name    : $c_ScriptName"
      Write-Log "# Version : $c_ScriptVersion"
      
      If($DisplayParameter) {
          Write-Log '# Parameters'
          (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly -ErrorAction SilentlyContinue).MyCommand.Parameters.GetEnumerator() `
          | ForEach-Object {
              Try { Write-Log "#    $($_.Key) : $(Get-Variable -Name $_.Key -ValueOnly -ErrorAction Stop)" } Catch {}
          }
      }

      If($c_CheckRunAsAdmin) {
          Write-Log '# Check run as administrator' -NoNewLine
          If((New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
              Write-Log ': OK' -Status
          } Else {
              Write-Log ': KO' 'ERR' -Status
              End-Script
          }
      }
  
      If($c_CheckMinimalVersion) {
          Write-Log "# Check minimum version $c_MinimalVersion" -NoNewLine
          If($c_MinimalVersion.Split('.')[0] -lt $Host.Version.Major -or ($c_MinimalVersion.Split('.')[0] -eq $Host.Version.Major -and $c_MinimalVersion.Split('.')[1] -le $Host.Version.Minor)) {
              Write-Log ': OK' -Status
          } Else {
              Write-Log ': KO' 'ERR' -Status
              End-Script
          }
      }
  
  }
  
  Function End-Script {
  <# 
  .Description 
  Effectue une stat des success, failed et warning. Log les rÃ©sultats et ferme le script
  .Example
  C:\PS>End-Script
  #>     
      Param(
          [switch] $wait
      )
      
      Write-Log
      if ($g_Success -ge 0) {
          Write-Log "# Success    : $g_Success"
      }
     
      if ($g_Items -ge 0) {
          Write-Log "# Proceeded  : $g_Items"
      }
      if (($g_Items+$g_Success+$g_Fail) -ge 0) {
          Write-Log "# "
      }
  
      Write-Log "# Warning(s) : $g_Warnings"
      Write-Log "# Error(s)   : $g_Errors"
      
      Write-Log '### END ###'
      Write-Log '###--------------------------------------------------------------------------------'
  
      If($g_Errors -ne 0) {
          $g_ExitCode += 1
      }
  
      if ($wait) {
          Read-Host -Prompt "Press enter to terminate "
      }
  
      Exit $g_ExitCode
  }
  
  Function Get-IniContent 
  { 
      <# 
      .Description 
          RÃ©cupÃ©rer le contenu d'un fichier INI en tant que variables
           
          #Requiert -Version 2.0 de powershell
          # http://www.microsoft.com/en-us/download/confirmation.aspx?id=20430
           
      .Inputs 
          System.String 
      .Outputs 
          System.Collections.Hashtable
          
      .Parameter FilePath 
          SpÃ©cifie le path du fichier ini
          
      .Example 
          $ReadINIfile = Get-IniContent "C:\myinifile.ini" 
          ----------- 
          Description 
          MÃ©morise le chemin c:\myinifile.ini dans la variable $ReadINIfile 
          
       .Example 
          C:\PS>$ReadINIfile = Get-IniContent "c:\settings.ini" 
          C:\PS>$ReadINIfile["Section"]["Key"] 
          ----------- 
          Description 
          RÃ©cupÃ¨re la valeur de "Key" de la section "Section" depuis le fichier INI C:\settings.ini  
      #> 
  #----------------------------------------------------------------------------------------------------
      [CmdletBinding()] 
      Param( 
          [ValidateNotNullOrEmpty()] 
          [ValidateScript({(Test-Path $_) -and ((Get-Item $_).Extension -eq ".ini")})] 
          [Parameter(ValueFromPipeline=$False,Mandatory=$False)] 
          [string]$FilePath 
      ) 
       
      Begin 
          {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"} 
           
      Process 
      { 
          Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath" 
               
          $ini = @{} 
          switch -regex -file $FilePath 
          { 
              "^\[(.+)\]$" # Section 
              { 
                  $section = $matches[1] 
                  $ini[$section] = @{} 
                  $CommentCount = 0 
              } 
              "^(;.*)$" # Comment 
              { 
                  if (!($section)) 
                  { 
                      $section = "No-Section" 
                      $ini[$section] = @{} 
                  } 
                  $value = $matches[1] 
                  $CommentCount = $CommentCount + 1 
                  $name = "Comment" + $CommentCount 
                  $ini[$section][$name] = $value 
              }  
              "(.+?)=(.*)" # Key 
              { 
                  if (!($section)) 
                  { 
                      $section = "No-Section" 
                      $ini[$section] = @{} 
                  } 
                  $name,$value = $matches[1..2] 
                  $ini[$section][$name] = $value 
              } 
          } 
          Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $path" 
          Return $ini 
      } 
           
      End 
          {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"} 
  }
  


  
        
  
  
  # ===================================================================================================
  # INITIALISATION
  # ===================================================================================================
  
  $c_ScriptPath=try{Split-Path -Path $MyInvocation.MyCommand.Path -Parent}catch{$c_ScriptPath=Convert-Path (Get-Location -PSProvider FileSystem)}
  New-Variable -Name c_ScriptName           -Option AllScope -Force -Value $MyInvocation.MyCommand.Name
  New-Variable -Name c_ScriptPath           -Option AllScope -Force -Value $c_ScriptPath
  New-Variable -Name c_ScriptVersion        -Option AllScope -Force -Value '0.01'
  New-Variable -Name c_ScriptExecDate       -Option AllScope -Force -Value (Get-Date)
  New-Variable -Name c_LogPath              -Option AllScope -Force -Value ('{0}\Logs\{1}_{2}.log' -f $c_ScriptPath, (Get-Date -Date $c_ScriptExecDate -UFormat '%Y%m%d%H%M%S'), [Regex]::Replace($c_ScriptName, '\.ps1$', ''))
  
  New-Variable -Name c_CreateLogFile        -Option AllScope -Force -Value $true
  New-Variable -Name c_CheckRunAsAdmin      -Option AllScope -Force -Value $false
  New-Variable -Name c_CheckMinimalVersion  -Option AllScope -Force -Value $false
  New-Variable -Name c_MinimalVersion       -Option AllScope -Force -Value "4.0"
  
  New-Variable -Name g_Success              -Option AllScope -Force -Value 0
  New-Variable -Name g_Items                -Option AllScope -Force -Value 0
  New-Variable -Name g_Errors               -Option AllScope -Force -Value 0
  New-Variable -Name g_Warnings             -Option AllScope -Force -Value 0
  New-Variable -Name g_ExitCode             -Option AllScope -Force -Value 0
  
  Set-Location $c_ScriptPath
  Start-Script -DisplayParameter -Color
  Log-Start -LogPath (join-path $c_ScriptPath "Logs") -LogName (Get-item $c_LogPath).Name -ScriptVersion $c_ScriptVersion
  
  $ErrorActionPreference = 'Continue'
  
  Trap {
      Write-Log
      Write-Log "Unknown error : $($_.Exception.Message) / $($_.ScriptStackTrace)" 'ERR'
      End-Script
  }
  

  # ===================================================================================================
  # Lecture du fichier INI
  # ===================================================================================================
  
  # RÃ©cupÃ©ration chemin du script + Nom du script + Nom du fichier INI (le nom du INI doit Ãªtre identique Ã  celui du script)
  Write-log "# Loading ini"
  Write-log "# PSCommandPath:$PSCommandPath"
  $PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
  $scriptName = $c_ScriptName.TrimEnd("ps1")
  $INIname = $scriptName + "ini"
  $iniPath = $c_ScriptPath + "\" + $INIname
  
  # rÃ©cupÃ¨re le contenu du fichier INI
  $ReadINIfile = Get-IniContent ($iniPath) 		
  
  # rÃ©cupÃ¨re les variables
  [string]$AppId=$ReadINIfile["Office365"]["AppId"]
  [string]$TenantID=$ReadINIfile["Office365"]["TenantID"]
  [string]$CertificateThumbprint=$ReadINIfile["Office365"]["CertificateThumbprint"]
  [string]$AppSecret=$ReadINIfile["Office365"]["AppSecret"]
  [string]$Sender=$ReadINIfile["Mail"]["Sender"]
  [string]$Recipient=$ReadINIfile["Mail"]["Recipient"]
  [string]$CSVpath=$ReadINIfile["CSV"]["Path"]
  
  # ===================================================================================================
  # MAIN
  # ===================================================================================================
  
  write-log "### START ###"

  write-log "---------- Connecting to MG Graph ----------"

 # Connect-MgGraph -AppId $AppId -TenantId $TenantID -CertificateThumbprint $CertificateThumbprint

# Construct URI and body needed for authentication
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$body = @{
    client_id     = $AppId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $AppSecret
    grant_type    = "client_credentials"
}
$tokenRequest = Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing
# Unpack Access Token
$token = ($tokenRequest.Content | ConvertFrom-Json).access_token
$Headers = @{
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $Token" }
Connect-MgGraph -AccessToken $token
   
$1 = $(get-date).AddDays(-7)
 $signInsPopImap = Get-MgAuditLogSignIn -All -Filter "CreatedDateTime gt $($1.ToString("yyyy-MM-ddTHH:mm:ssZ")) and (ClientAppUsed eq 'POP3' or ClientAppUsed eq 'IMAP4')" 

$FirstShoot = @()
foreach ($status in $signInsPopImap) {
$extract = $status | select UserDisplayName,UserPrincipalName,CreatedDateTime,ClientAppUsed
$extract | Add-Member -MemberType NoteProperty -Name Status -Value $null -Force
$Add = $($status.Status.FailureReason)
if ($Add){
if ($Add -eq "Other.") {
$extract.Status ="Success"
$extract.Status
$FirstShoot += $extract
}else{
$extract.Status ="Failure"}
$extract.Status
}
else {
$Add
$extract.Status ="Success"
$extract.Status
$FirstShoot += $extract
}
$Add = $null
}

$dedoublonage = $FirstShoot |  Sort-Object -Property CreatedDateTime
$dedoublonagetri = $dedoublonage | Sort-Object -Property UserPrincipalName -Unique 
$CSVpath = $CSVpath -replace ('"','')
$csvName = "PopImapUsage-" + $(Get-Date -Format MM-dd-yyyy-HHmmss) + ".csv"
$exportcsv = $CSVpath + $csvName 
$dedoublonagetri | Export-csv -LiteralPath $exportcsv -NoClobber -NoTypeInformation -Encoding UTF8 -Delimiter ";"

$Headers = @{
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $Token" }

# Define some variables for the message
#HTML header with styles
$htmlhead="<html>
     <style>
      BODY{font-family: Arial; font-size: 11pt;}
	H1{font-size: 22px;}
	H2{font-size: 18px; padding-top: 10px;}
	H3{font-size: 16px; padding-top: 8px;}
    </style>"
#Header for the message

      $a = "<style>"
      $a = $a + "TABLE{border-width: 2px;border-style: solid;border-color: black;border-collapse: collapse;font-family: Arial;}"
      $a = $a + "TH{border-width: 1px;padding: 20px;border-style: solid;border-color: black;background-color:#0066FF;color: white;}"
      $a = $a + "TD{border-width: 1px;padding: 20px;border-style: solid;border-color: black;}"
      $a = $a + "</style>"
    $table =   $dedoublonagetri | ConvertTo-HTML -head $a
$HtmlBody = "<body>
     <h1>Report POP/IMAP Mailboxes of $(Get-Date -Format MM-dd-yyyy) </h1>
     <p><strong>Generated:</strong> $(Get-Date -Format g)</p>
     $table"

# Define attachment to send to new users

$AttachmentFile = Get-Content $exportcsv -Encoding Byte
$ContentBase64 = [convert]::ToBase64String($AttachmentFile)

      $EmailRecipient = $Recipient

      $MsgSubject = "Report POP/IMAP Mailboxes of " + $(Get-Date -Format g) +" for the last 7 Days"

       $MsgFrom = $Sender

      $HtmlMsg = "</body></html>" + $HtmlHead + $HtmlBody + $a
# Create message body and properties and send
        $MessageParams = @{
          "URI"         = "https://graph.microsoft.com/v1.0/users/$MsgFrom/sendMail"
          "Headers"     = $Headers
          "Method"      = "POST"
          "ContentType" = 'application/json'
          "Body" = (@{
                "message" = @{
                "subject" = $MsgSubject
                "body"    = @{
                    "contentType" = 'HTML' 
                     "content"     = $htmlMsg }
          "attachments" = @(
             @{
              "@odata.type" = "#microsoft.graph.fileAttachment"
              "name" = $csvName 
              "contenttype" = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
              "contentBytes" = $ContentBase64 } )  
           "toRecipients" = @(
           @{
             "emailAddress" = @{"address" = $EmailRecipient }
           } ) <# ,
            @{
             "emailAddress" = @{"address" = ""}
           } 
            ) 
        "ccRecipients" = @(
           @{
             "emailAddress" = @{"address" = $ccRecipient1 }
           } ,
            @{
             "emailAddress" = @{"address" = $ccRecipient2 }
           } )      #> 
         }
      }) | ConvertTo-JSON -Depth 15
   }
   # Send the message
   
   Write-Log "Sending Mail"
   Invoke-RestMethod @Messageparams
   $g_Success++

   Log-Finish -LogPath $c_LogPath -NoExit $True
   End-Script
