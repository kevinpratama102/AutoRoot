#Comma separated list of domain controllers to ask...

$DCNAMES = "DC1,DC2,DC3" 

#Check for the events that indicate incompatible devices, start at august 10th (patches were delivered at the 11th).
#See https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc#DetectingNon-compliant

#Make sure you got the -After to you specific date format
$zerologonevents =  Get-Eventlog -Logname System -After 10.08.2020 -ComputerName $DCNAMES | Where-Object {$_.EventID -eq 5827 -or $_.EventID -eq 5828 -or $_.EventID -eq 5829 -or $_.EventID -eq 5830 -or $_.EventID -eq 5831} | Select-Object -Property TimeWritten, Source, EventID, Message

#Make it to be sendable in smtp body from array
$zerologoneventsString = $zerologonevents | Out-String

#Send the results via smtp mail
#make sure you set your smtp server
$EmailTo = "maik.linnemann@provit.info" 
$EmailFrom = "Event Checker <eventchecker@provit.info>"
$Subject = "Eventchecker: Result for Zero Login Events"
$Body = "Eventcheck was done..." + "`n" + "`n"
$Body += "----------------------------------------------"
$Body += $zerologoneventsString
$SMTPServer = "smtp.mydomain.tld" 
$SMTPMessage = New-Object System.Net.Mail.MailMessage($EmailFrom, $EmailTo, $Subject, $Body)
$SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 25) 
$SMTPClient.EnableSsl = $false 
$SMTPClient.Send($SMTPMessage)
