$dcnames = @("DC1","DC2","DC3")

$patchReleaseDate = (Get-Date "10.08.2020")

function getEvents($dc){

Get-WinEvent -Logname System -ComputerName $dc | Where-Object {$_.TimeCreated -ge $patchReleaseDate} | Where-Object {$_.Id -eq 5827 -or $_.Id -eq 5828 -or $_.Id -eq 5829 -or $_.Id -eq 5830 -or $_.Id -eq 5831} | Select-Object -Property TimeCreated, Id, Message

}

foreach ($dc in $dcnames){

getEvents($dc)

}
