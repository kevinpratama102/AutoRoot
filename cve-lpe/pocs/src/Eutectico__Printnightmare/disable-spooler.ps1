Get-Service -Name Spooler 

stop-service -Name Spooler -Force 

Get-Service -Name Spooler 

Set-Service -Name Spooler -StartupType Disabled 

Exit 
