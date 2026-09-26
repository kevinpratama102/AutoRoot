@echo on 

FOR /F %%i in (serverlist.txt) do ( 

winrs -r:%%i echo ################################################################# >> ./disable-spooler.log 

winrs -r:%%i echo Servername %%i >> ./disable-spooler.log 

winrs -r:%%i powershell -executionpolicy bypass stop-service -Name Spooler -Force -verbose >> ./disable-spooler.log 

winrs -r:%%i powershell -executionpolicy bypass Set-Service -Name Spooler -StartupType Disabled -verbose >> ./disable-spooler.log 

winrs -r:%%i powershell -executionpolicy bypass Get-Service -Name Spooler >> ./disable-spooler.log 

) 
