# CVE-2023-23397
CVE-2023-23397 Remediation Script (Powershell)

There are 3 PowerShell scripts.

If your patch management software uses an **evaluation** and a **remediation script**, use the respective files/scripts.

Alternatively, if you wish to just push out the update without the above, the **All In One script** will evaluate the current version of Microsoft Office and if it is not one of the versions listed in the script, it will force an Office update.

The all in one script can be run manually or pushed out directly to the endpoint.

**Note that the All In One Scripts and Remediation scripts will force an update without notfying the user. They will force close Office in order to update; adjust as desired.**

Endpoints with Office Versions listed in the script (up-to-date as of 3/17/23) will not have to go through the update process or have Office force closed.
