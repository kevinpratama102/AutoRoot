# MITRE ATT&CK Mapping

## T1059.001 - PowerShell
PowerShell was used to perform the suspicious execution sequence, including DNS resolution and payload delivery.

## T1105 - Ingress Tool Transfer
The payload archive `EDR-Freeze_1.0.zip` was downloaded to the host from external infrastructure.

## T1562 - Impair Defenses
EDRFreeze is associated with attempts to interfere with or bypass endpoint protection controls.

## T1218 - System Binary Proxy Execution
The execution of `WerFaultSecure.exe` in this context may reflect abuse of a legitimate Windows binary.

## T1071 / Network Communications
The host communicated externally during the observed execution chain.
