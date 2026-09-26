# zerologon
Check for events that indicate non compatible devices -> CVE-2020-1472
EventID 5827 EventID 5828 EventID 5829 EventID 5830 EventID 5831

In August Microsoft patched CVE-2020-1472. With that patch theres a waiting period until 9th of february 2021 where unsecure connections will be accepted. 
With the patch on 9th of february unsecure clients will be rejected.

https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc#DetectingNon-compliant

Script searches for the specific events on domain controllers to detect the unsecure devices.
