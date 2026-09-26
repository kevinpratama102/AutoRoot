#include <string>
#include <iostream>
#include <Windows.h>

#include "methods/methods.h"

BOOL IsUserAnAdmin() {
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    std::cout << "[DEBUG] Checking if user is an admin..." << std::endl;

    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        std::cerr << "[ERROR] Failed to allocate and initialize SID." << std::endl;
        return FALSE;
    }

    BOOL isMember = FALSE;
    if (!CheckTokenMembership(NULL, adminGroup, &isMember)) {
        std::cerr << "[ERROR] Failed to check token membership." << std::endl;
        isMember = FALSE;
    }

    FreeSid(adminGroup);
    std::cout << "[DEBUG] Admin check result: " << isMember << std::endl;
    return isMember;
}

int main(int argc, char* argv[]) {
    std::cout << "[DEBUG] Program started with " << argc << " arguments." << std::endl;

    if (argc < 1) {
        std::cerr << "Usage: <program> <method> [<filePath>]" << std::endl;
        return 1;
    }

    std::string methodString = argv[1];
    std::string filePath;

    if (argc >= 3) {
        filePath = argv[2];
    }
    else {
        filePath = "calc.exe";
        std::cout << "[DEBUG] No file path provided, defaulting to: " << filePath << std::endl;
    }

    std::cout << "[DEBUG] Method string: " << methodString << std::endl;
    std::cout << "[DEBUG] File path: " << filePath << std::endl;

    if (IsUserAnAdmin()) {
        std::cout << "[DEBUG] User is admin, executing with ShellExecuteEx..." << std::endl;

        if (filePath.find(" ") != std::string::npos) {
            filePath = "\"" + filePath + "\"";
            std::cout << "[DEBUG] File path contains spaces, adjusted to: " << filePath << std::endl;
        }

        SHELLEXECUTEINFOA StartProcess = { sizeof(StartProcess) };
        StartProcess.fMask = SEE_MASK_NOCLOSEPROCESS;
        StartProcess.lpFile = filePath.c_str();

        if (!ShellExecuteExA(&StartProcess)) {
            std::cerr << "[ERROR] ShellExecuteExA failed with error: " << GetLastError() << std::endl;
            return 1;
        }

        std::cout << "[DEBUG] Process launched successfully." << std::endl;
        return 0;
    }

    int method;
    try {
        method = std::stoi(methodString);
    }
    catch (std::exception& e) {
        std::cerr << "[ERROR] Invalid method number: " << methodString << " (" << e.what() << ")" << std::endl;
        return 1;
    }

    std::cout << "[DEBUG] Executing method: " << method << " with file: " << filePath << std::endl;

    if (method == 0) {
        std::cerr << "[ERROR] Method 0 is not allowed." << std::endl;
        return 1;
    }

    Methods::ExecuteMethod(method, filePath);
    std::cout << "[DEBUG] Method executed." << std::endl;

    return 0;
}
