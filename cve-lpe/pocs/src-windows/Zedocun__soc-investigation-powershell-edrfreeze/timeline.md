# Timeline

## Chronological sequence

1. PowerShell execution observed  
   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

2. DNS query to `github.com`  
   Resolved IP: `140.82.113.4`

3. ZIP archive created in Downloads  
   `C:\Users\LetsDefend\Downloads\EDR-Freeze_1.0.zip`

4. Temporary PowerShell execution policy file created  
   `C:\Users\LetsDefend\AppData\Local\Temp\__PSScriptPolicyTest_*.ps1`

5. Payload executed  
   `C:\Users\LetsDefend\Downloads\EDR-Freeze_1.0.exe`

6. Child process spawned  
   `C:\Windows\System32\WerFaultSecure.exe`

7. Outbound network activity observed  
   Including: `23.221.245.214`, `185.199.111.133`, `23.78.9.173`
