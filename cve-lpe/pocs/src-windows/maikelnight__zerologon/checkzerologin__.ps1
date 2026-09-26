
$dcnames = @("DC1","DC2","DC3")

$patchReleaseDate = (Get-Date "10.08.2020")


function getEvents($dc){

$outarray = @()

$out = @(

    Get-WinEvent -Logname System -ComputerName $dc | Where-Object {$_.TimeCreated -ge $patchReleaseDate} | Where-Object {$_.Id -eq 5827 -or $_.Id -eq 5828 -or $_.Id -eq 5829 -or $_.Id -eq 5830 -or $_.Id -eq 5831} | Select-Object -Property TimeCreated, Id, Message

)

foreach ($element in $out) {
    
    $TimeCreated = $element.TimeCreated
    $Id = $element.Id
    $Message = $element.Message

    $outarray += @{"Datum" = "$TimeCreated"; "EventID" = "$Id"; "Message" = "$Message"; "DomCtrl" = "$dc"}

}


$zerologoneventsString = $outarray | Out-String

$EmailTo = "maik.linnemann@provit.info" 
$EmailFrom = "Event Checker <eventchecker@provit.info>"
$Subject = "Eventchecker: Ergebnis f. Zero Login Events - DC = $dc"
$Body = "Eventcheck was done... @dc: $dc" + "`n" + "`n"
$Body += "----------------------------------------------"
$Body += $zerologoneventsString
$SMTPServer = "SMTPSERVER" 
$SMTPMessage = New-Object System.Net.Mail.MailMessage($EmailFrom, $EmailTo, $Subject, $Body)
$SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 25) 
$SMTPClient.EnableSsl = $false 
$SMTPClient.Send($SMTPMessage)

}

foreach ($dc in $dcnames){

getEvents($dc)

}



