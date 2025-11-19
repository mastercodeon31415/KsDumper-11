#pragma once
#include <ntddk.h>
typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS* Process;
	BOOLEAN KernelApcInProgress;
	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS;
typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID BaseAddress;
	PVOID AllocationBase;
	INT32 AllocationProtect;
	SIZE_T RegionSize;
	INT32 State;
	INT32 Protect;
	INT32 Type;
} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;
// --------------------------------------------------------------------------------
// PEB / TEB / LDR Definitions for Module Enumeration
// --------------------------------------------------------------------------------
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandler;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	// ... We don't need the rest for this task
} PEB, * PPEB;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// ...
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
// --------------------------------------------------------------------------------
// WoW64 (32-bit) Definitions
// --------------------------------------------------------------------------------
typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandler;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;
typedef struct _PEB32
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr; // Points to PEB_LDR_DATA32
	// ...
} PEB32, * PPEB32;
typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	// ...
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
// --------------------------------------------------------------------------------
// Function Prototypes
// --------------------------------------------------------------------------------
NTKERNELAPI NTSTATUS IoCreateDriver(IN PUNICODE_STRING DriverName, OPTIONAL IN PDRIVER_INITIALIZE InitializationFunction);
NTKERNELAPI VOID KeStackAttachProcess(__inout struct _KPROCESS* PROCESS, __out PRKAPC_STATE ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(__in PRKAPC_STATE ApcState);
NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(IN PEPROCESS FromProcess, IN PVOID FromAddress, IN PEPROCESS ToProcess, OUT PVOID ToAddress, IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode, OUT PSIZE_T NumberOfBytesCopied);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN MEMORY_INFORMATION_CLASS MemoryInformationClass, OUT PVOID MemoryInformation, IN SIZE_T MemoryInformationLength, OUT PSIZE_T ReturnLength OPTIONAL);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId, OUT PEPROCESS* Process);
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);