// Relative Path: Driver\ProcessLister.c
#include "NTUndocumented.h"
#include "ProcessLister.h"
#include "Utility.h"

#define POOL_TAG_PROC 'corP'
#define POOL_TAG_NAME 'emaN'
#define POOL_TAG_MODS 'sdoM'

// Helper: Allows ReadOnly and ReadWrite memory for scanning
static BOOLEAN IsAddressSafeForRead(PVOID pointer, SIZE_T size)
{
	MEMORY_BASIC_INFORMATION memInfo;
	if (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), pointer, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), NULL)))
	{
		if (memInfo.State == MEM_COMMIT)
		{
			if ((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize >= (ULONG_PTR)pointer + size)
			{
				// Allowed protections: ReadOnly, ReadWrite, WriteCopy, ExecuteRead, ExecuteReadWrite, ExecuteWriteCopy
				if (memInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
					PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
				{
					// Disallow Guard pages or NoAccess
					if (!(memInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
					{
						return TRUE;
					}
				}
			}
		}
	}
	return FALSE;
}

// Helper: Verifies if a memory address points to a valid PE Header (MZ + PE Signature)
static BOOLEAN IsValidPEHeader(PVOID baseAddress, PULONG outSize)
{
	*outSize = 0;

	// 1. Check DOS Header
	if (IsAddressSafeForRead(baseAddress, sizeof(IMAGE_DOS_HEADER)))
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)baseAddress;
		if (dos->e_magic == 0x5A4D) // 'MZ'
		{
			// Sanity check e_lfanew (Must be within first page usually, definitely > 0)
			if (dos->e_lfanew > 0 && dos->e_lfanew < 0x1000)
			{
				PVOID ntHeaderPtr = (PVOID)((ULONG_PTR)baseAddress + dos->e_lfanew);

				// 2. Check NT Header Signature
				if (IsAddressSafeForRead(ntHeaderPtr, sizeof(PE_HEADER)))
				{
					PPE_HEADER nt = (PPE_HEADER)ntHeaderPtr;
					if (nt->Signature[0] == 'P' && nt->Signature[1] == 'E' && nt->Signature[2] == 0 && nt->Signature[3] == 0)
					{
						// It is a valid PE. Try to get SizeOfImage.
						// SizeOfImage is at offset 56 in the OptionalHeader for both 32 and 64 bit.
						// OptionalHeader starts immediately after PE Header (4 bytes) + File Header (20 bytes) = 24 bytes (0x18)
						PVOID sizeFieldPtr = (PVOID)((ULONG_PTR)ntHeaderPtr + 0x18 + 56);

						if (IsAddressSafeForRead(sizeFieldPtr, sizeof(ULONG)))
						{
							*outSize = *(PULONG)sizeFieldPtr;
						}
						return TRUE;
					}
				}
			}
		}
	}
	return FALSE;
}

static PSYSTEM_PROCESS_INFORMATION GetRawProcessList()
{
	ULONG bufferSize = 0;
	PVOID bufferPtr = NULL;
	NTSTATUS status;

	status = ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &bufferSize);

	do
	{
		if (bufferSize == 0) break;
		bufferSize += 0x2000;

		bufferPtr = ExAllocatePoolWithTag(NonPagedPool, bufferSize, POOL_TAG_PROC);

		if (bufferPtr == NULL) return NULL;

		status = ZwQuerySystemInformation(SystemProcessInformation, bufferPtr, bufferSize, &bufferSize);

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePoolWithTag(bufferPtr, POOL_TAG_PROC);
			bufferPtr = NULL;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(status) && bufferPtr != NULL)
	{
		ExFreePoolWithTag(bufferPtr, POOL_TAG_PROC);
		return NULL;
	}

	return (PSYSTEM_PROCESS_INFORMATION)bufferPtr;
}

static ULONG CalculateProcessListOutputSize(PSYSTEM_PROCESS_INFORMATION rawProcessList)
{
	int size = 0;
	if (!rawProcessList) return 0;

	PSYSTEM_PROCESS_INFORMATION current = rawProcessList;

	while (TRUE)
	{
		size += sizeof(PROCESS_SUMMARY);
		if (current->NextEntryOffset == 0) break;
		current = (PSYSTEM_PROCESS_INFORMATION)(((CHAR*)current) + current->NextEntryOffset);
	}
	return size;
}

static BOOLEAN IsDotNetModule(UNICODE_STRING* dllName)
{
	if (dllName == NULL || dllName->Buffer == NULL) return FALSE;

	WCHAR* buffer = dllName->Buffer;
	USHORT len = dllName->Length / sizeof(WCHAR);

	for (USHORT i = 0; i < len; i++)
	{
		if (len - i >= 4)
		{
			if ((buffer[i] == 'c' || buffer[i] == 'C') &&
				(buffer[i + 1] == 'l' || buffer[i + 1] == 'L') &&
				(buffer[i + 2] == 'r' || buffer[i + 2] == 'R') &&
				(buffer[i + 3] == '.'))
				return TRUE;
		}
		if (len - i >= 7)
		{
			if ((buffer[i] == 'm' || buffer[i] == 'M') &&
				(buffer[i + 1] == 's' || buffer[i + 1] == 'S') &&
				(buffer[i + 2] == 'c' || buffer[i + 2] == 'C') &&
				(buffer[i + 3] == 'o' || buffer[i + 3] == 'O') &&
				(buffer[i + 4] == 'r' || buffer[i + 4] == 'R') &&
				(buffer[i + 5] == 'e' || buffer[i + 5] == 'E') &&
				(buffer[i + 6] == 'e' || buffer[i + 6] == 'E'))
				return TRUE;
		}
	}
	return FALSE;
}

static PLDR_DATA_TABLE_ENTRY_PE GetMainModuleDataTableEntry(PPEB64_PE peb, PBOOLEAN isDotNet)
{
	*isDotNet = FALSE;
	PLDR_DATA_TABLE_ENTRY_PE mainEntry = NULL;

	if (IsAddressSafeForRead(peb, sizeof(PEB64_PE)))
	{
		if (peb->Ldr)
		{
			if (IsAddressSafeForRead(peb->Ldr, sizeof(PEB_LDR_DATA_PE)))
			{
				if (!peb->Ldr->Initialized)
				{
					int initLoadCount = 0;
					while (!peb->Ldr->Initialized && initLoadCount++ < 4) DriverSleep(250);
				}

				if (peb->Ldr->Initialized)
				{
					mainEntry = CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY_PE, InLoadOrderLinks);

					PLIST_ENTRY listHead = &peb->Ldr->InLoadOrderModuleList;
					PLIST_ENTRY current = listHead->Flink;
					int safety = 0;

					while (current != listHead && safety < 500)
					{
						PLDR_DATA_TABLE_ENTRY_PE entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_PE, InLoadOrderLinks);
						if (IsAddressSafeForRead(entry, sizeof(LDR_DATA_TABLE_ENTRY_PE)))
						{
							if (IsDotNetModule(&entry->BaseDllName)) *isDotNet = TRUE;
						}
						current = current->Flink;
						if (!IsAddressSafeForRead(current, sizeof(LIST_ENTRY))) break;
						safety++;
					}
				}
			}
		}
	}
	return mainEntry;
}

static PLDR_DATA_TABLE_ENTRY32 GetMainModuleDataTableEntry32(PPEB32 peb, PBOOLEAN isDotNet)
{
	*isDotNet = FALSE;
	PLDR_DATA_TABLE_ENTRY32 mainEntry = NULL;

	if (IsAddressSafeForRead(peb, sizeof(PEB32)))
	{
		PPEB_LDR_DATA32 ldr = (PPEB_LDR_DATA32)(ULONG_PTR)peb->Ldr;
		if (IsAddressSafeForRead(ldr, sizeof(PEB_LDR_DATA32)))
		{
			if (!ldr->Initialized)
			{
				int initLoadCount = 0;
				while (!ldr->Initialized && initLoadCount++ < 4) DriverSleep(250);
			}

			if (ldr->Initialized)
			{
				mainEntry = CONTAINING_RECORD(ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

				PLIST_ENTRY32 listHead = &ldr->InLoadOrderModuleList;
				PLIST_ENTRY32 current = (PLIST_ENTRY32)(ULONG_PTR)listHead->Flink;
				int safety = 0;

				while (current != (PLIST_ENTRY32)(ULONG_PTR)listHead && safety < 500)
				{
					PLDR_DATA_TABLE_ENTRY32 entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
					if (IsAddressSafeForRead(entry, sizeof(LDR_DATA_TABLE_ENTRY32)))
					{
						UNICODE_STRING tempName;
						tempName.Length = entry->BaseDllName.Length;
						tempName.MaximumLength = entry->BaseDllName.MaximumLength;
						tempName.Buffer = (PWCH)(ULONG_PTR)entry->BaseDllName.Buffer;

						if (IsDotNetModule(&tempName)) *isDotNet = TRUE;
					}
					current = (PLIST_ENTRY32)(ULONG_PTR)current->Flink;
					if (!IsAddressSafeForRead(current, sizeof(LIST_ENTRY32))) break;
					safety++;
				}
			}
		}
	}
	return mainEntry;
}

NTSTATUS GetProcessList(PVOID listedProcessBuffer, INT32 bufferSize, PINT32 requiredBufferSize, PINT32 processCount)
{
	PPROCESS_SUMMARY processSummary = (PPROCESS_SUMMARY)listedProcessBuffer;
	PSYSTEM_PROCESS_INFORMATION rawProcessList = GetRawProcessList();
	PVOID listHeadPointer = rawProcessList;
	*processCount = 0;

	if (rawProcessList)
	{
		int expectedBufferSize = CalculateProcessListOutputSize(rawProcessList);
		if (!listedProcessBuffer || bufferSize < expectedBufferSize)
		{
			*requiredBufferSize = expectedBufferSize;
			ExFreePoolWithTag(listHeadPointer, POOL_TAG_PROC);
			return STATUS_INFO_LENGTH_MISMATCH;
		}

		PSYSTEM_PROCESS_INFORMATION currentEntry = rawProcessList;
		while (TRUE)
		{
			PEPROCESS targetProcess;
			PKAPC_STATE state = NULL;

			if (NT_SUCCESS(PsLookupProcessByProcessId(currentEntry->UniqueProcessId, &targetProcess)))
			{
				PVOID mainModuleBase = NULL;
				PVOID mainModuleEntryPoint = NULL;
				UINT32 mainModuleImageSize = 0;
				PWCHAR mainModuleFileName = NULL;
				BOOLEAN isWow64 = 0;
				BOOLEAN isDotNet = 0;

				__try
				{
					KeStackAttachProcess(targetProcess, &state);
					__try
					{
						mainModuleBase = PsGetProcessSectionBaseAddress(targetProcess);
						if (mainModuleBase)
						{
							PVOID wow64Process = PsGetProcessWow64Process(targetProcess);
							if (wow64Process)
							{
								PPEB32 peb = (PPEB32)wow64Process;
								if (peb)
								{
									PLDR_DATA_TABLE_ENTRY32 mainModuleEntry = GetMainModuleDataTableEntry32(peb, &isDotNet);
									if (mainModuleEntry && IsAddressSafeForRead(mainModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY32)))
									{
										mainModuleEntryPoint = (PVOID)(ULONG_PTR)mainModuleEntry->EntryPoint;
										mainModuleImageSize = mainModuleEntry->SizeOfImage;
										isWow64 = TRUE;
										mainModuleFileName = ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(WCHAR), POOL_TAG_NAME);
										if (mainModuleFileName)
										{
											RtlZeroMemory(mainModuleFileName, 256 * sizeof(WCHAR));
											if (mainModuleEntry->FullDllName.Buffer)
											{
												PWCH src = (PWCH)(ULONG_PTR)mainModuleEntry->FullDllName.Buffer;
												if (IsAddressSafeForRead(src, mainModuleEntry->FullDllName.Length))
													RtlCopyMemory(mainModuleFileName, src, mainModuleEntry->FullDllName.Length);
											}
										}
									}
								}
							}
							else
							{
								PPEB64_PE peb = (PPEB64_PE)PsGetProcessPeb(targetProcess);
								if (peb)
								{
									PLDR_DATA_TABLE_ENTRY_PE mainModuleEntry = GetMainModuleDataTableEntry(peb, &isDotNet);
									if (mainModuleEntry && IsAddressSafeForRead(mainModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY_PE)))
									{
										mainModuleEntryPoint = mainModuleEntry->EntryPoint;
										mainModuleImageSize = mainModuleEntry->SizeOfImage;
										isWow64 = FALSE;
										mainModuleFileName = ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(WCHAR), POOL_TAG_NAME);
										if (mainModuleFileName)
										{
											RtlZeroMemory(mainModuleFileName, 256 * sizeof(WCHAR));
											if (mainModuleEntry->FullDllName.Buffer)
											{
												if (IsAddressSafeForRead(mainModuleEntry->FullDllName.Buffer, mainModuleEntry->FullDllName.Length))
													RtlCopyMemory(mainModuleFileName, mainModuleEntry->FullDllName.Buffer, mainModuleEntry->FullDllName.Length);
											}
										}
									}
								}
							}
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {}
				}
				__finally
				{
					KeUnstackDetachProcess(&state);
				}

				if (mainModuleFileName)
				{
					RtlCopyMemory(processSummary->MainModuleFileName, mainModuleFileName, 256 * sizeof(WCHAR));
					ExFreePoolWithTag(mainModuleFileName, POOL_TAG_NAME);
					processSummary->ProcessId = (INT32)(ULONG_PTR)currentEntry->UniqueProcessId;
					processSummary->MainModuleBase = mainModuleBase;
					processSummary->MainModuleEntryPoint = mainModuleEntryPoint;
					processSummary->MainModuleImageSize = mainModuleImageSize;
					processSummary->WOW64 = isWow64;
					processSummary->IsDotNet = isDotNet;
					processSummary++;
					(*processCount)++;
				}
				ObDereferenceObject(targetProcess);
			}
			if (currentEntry->NextEntryOffset == 0) break;
			currentEntry = (PSYSTEM_PROCESS_INFORMATION)(((CHAR*)currentEntry) + currentEntry->NextEntryOffset);
		}
		ExFreePoolWithTag(listHeadPointer, POOL_TAG_PROC);
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS GetProcessModules(INT32 targetProcessId, PVOID bufferAddress, INT32 bufferSize, PINT32 moduleCount)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS targetProcess;
	KAPC_STATE state;
	PKERNEL_MODULE_INFO tempBuffer = NULL;
	ULONG maxModules = bufferSize / sizeof(KERNEL_MODULE_INFO);
	ULONG foundModules = 0;

	if (maxModules == 0 || bufferSize > 1024 * 1024 * 10) return STATUS_INVALID_PARAMETER;

	tempBuffer = (PKERNEL_MODULE_INFO)ExAllocatePoolWithTag(PagedPool, bufferSize, POOL_TAG_MODS);
	if (!tempBuffer) return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(tempBuffer, bufferSize);

	status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetProcessId, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(tempBuffer, POOL_TAG_MODS);
		return status;
	}

	KeStackAttachProcess(targetProcess, &state);

	// 1. Standard PEB Walk
	__try
	{
		PVOID wow64Process = PsGetProcessWow64Process(targetProcess);
		if (wow64Process != NULL)
		{
			PPEB32 peb32 = (PPEB32)wow64Process;
			if (IsAddressSafeForRead(peb32, sizeof(PEB32)))
			{
				PPEB_LDR_DATA32 ldr32 = (PPEB_LDR_DATA32)(ULONG_PTR)peb32->Ldr;
				if (IsAddressSafeForRead(ldr32, sizeof(PEB_LDR_DATA32)))
				{
					PLIST_ENTRY32 listHead = &ldr32->InLoadOrderModuleList;
					PLIST_ENTRY32 current = (PLIST_ENTRY32)(ULONG_PTR)listHead->Flink;
					while (current != listHead && foundModules < maxModules)
					{
						PLDR_DATA_TABLE_ENTRY32 entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
						if (IsAddressSafeForRead(entry, sizeof(LDR_DATA_TABLE_ENTRY32)) && entry->DllBase != 0)
						{
							tempBuffer[foundModules].BaseAddress = (PVOID)(ULONG_PTR)entry->DllBase;
							tempBuffer[foundModules].SizeOfImage = entry->SizeOfImage;
							if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0)
							{
								PWCHAR src = (PWCHAR)(ULONG_PTR)entry->FullDllName.Buffer;
								if (IsAddressSafeForRead(src, entry->FullDllName.Length))
								{
									USHORT len = entry->FullDllName.Length;
									if (len > sizeof(tempBuffer[0].FullPathName) - 2) len = sizeof(tempBuffer[0].FullPathName) - 2;
									RtlCopyMemory(tempBuffer[foundModules].FullPathName, src, len);
								}
							}
							foundModules++;
						}
						current = (PLIST_ENTRY32)(ULONG_PTR)current->Flink;
						if (!IsAddressSafeForRead(current, sizeof(LIST_ENTRY32))) break;
					}
				}
			}
		}
		else
		{
			PPEB peb = PsGetProcessPeb(targetProcess);
			if (IsAddressSafeForRead(peb, sizeof(PEB)))
			{
				PPEB_LDR_DATA ldr = peb->Ldr;
				if (IsAddressSafeForRead(ldr, sizeof(PEB_LDR_DATA)))
				{
					PLIST_ENTRY listHead = &ldr->InLoadOrderModuleList;
					PLIST_ENTRY current = listHead->Flink;
					while (current != listHead && foundModules < maxModules)
					{
						PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
						if (IsAddressSafeForRead(entry, sizeof(LDR_DATA_TABLE_ENTRY)) && entry->DllBase != NULL)
						{
							tempBuffer[foundModules].BaseAddress = entry->DllBase;
							tempBuffer[foundModules].SizeOfImage = entry->SizeOfImage;
							if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0)
							{
								if (IsAddressSafeForRead(entry->FullDllName.Buffer, entry->FullDllName.Length))
								{
									USHORT len = entry->FullDllName.Length;
									if (len > sizeof(tempBuffer[0].FullPathName) - 2) len = sizeof(tempBuffer[0].FullPathName) - 2;
									RtlCopyMemory(tempBuffer[foundModules].FullPathName, entry->FullDllName.Buffer, len);
								}
							}
							foundModules++;
						}
						current = current->Flink;
						if (!IsAddressSafeForRead(current, sizeof(LIST_ENTRY))) break;
					}
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	// 2. VAD Scan for Unlinked/.NET/Manual Mapped Modules
	__try
	{
		PVOID baseAddr = (PVOID)0;
		MEMORY_BASIC_INFORMATION memInfo;
		UCHAR pathBuffer[1024];
		PUNICODE_STRING pathString = (PUNICODE_STRING)pathBuffer;

		while (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), baseAddr, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), NULL)))
		{
			if (memInfo.State == MEM_COMMIT)
			{
				// CHANGED: Added PAGE_READWRITE and PAGE_WRITECOPY to detect packed modules
				BOOLEAN isExecutable = (memInfo.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
				BOOLEAN isReadOnly = (memInfo.Protect & PAGE_READONLY);
				BOOLEAN isReadWrite = (memInfo.Protect & (PAGE_READWRITE | PAGE_WRITECOPY));

				if ((isExecutable || isReadOnly || isReadWrite) && !(memInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
				{
					BOOLEAN alreadyFound = FALSE;
					for (ULONG i = 0; i < foundModules; i++)
					{
						ULONG_PTR start = (ULONG_PTR)tempBuffer[i].BaseAddress;
						ULONG_PTR end = start + tempBuffer[i].SizeOfImage;
						ULONG_PTR regStart = (ULONG_PTR)memInfo.BaseAddress;
						if (regStart >= start && regStart < end) { alreadyFound = TRUE; break; }
					}

					if (!alreadyFound && foundModules < maxModules)
					{
						// Enforce VALID PE HEADER check to filter out random RW data
						ULONG peSize = 0;
						if (IsValidPEHeader(memInfo.BaseAddress, &peSize))
						{
							if (peSize == 0) peSize = (ULONG)memInfo.RegionSize;

							tempBuffer[foundModules].BaseAddress = memInfo.BaseAddress;
							tempBuffer[foundModules].SizeOfImage = peSize;

							SIZE_T retLen = 0;
							NTSTATUS pathStatus = ZwQueryVirtualMemory(ZwCurrentProcess(),
								memInfo.BaseAddress,
								MemoryMappedFilenameInformation,
								pathBuffer,
								sizeof(pathBuffer),
								&retLen);

							if (NT_SUCCESS(pathStatus) && pathString->Buffer && pathString->Length > 0)
							{
								USHORT len = pathString->Length;
								if (len > sizeof(tempBuffer[0].FullPathName) - 2) len = sizeof(tempBuffer[0].FullPathName) - 2;
								RtlCopyMemory(tempBuffer[foundModules].FullPathName, pathString->Buffer, len);
							}
							else
							{
								WCHAR manualName[] = L"Unlinked_Module_";
								RtlZeroMemory(tempBuffer[foundModules].FullPathName, sizeof(tempBuffer[foundModules].FullPathName));
								RtlCopyMemory(tempBuffer[foundModules].FullPathName, manualName, sizeof(manualName));
							}

							foundModules++;
						}
					}
				}
			}
			PVOID nextAddr = (PVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);
			if (nextAddr <= baseAddr) break;
			baseAddr = nextAddr;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	KeUnstackDetachProcess(&state);
	ObDereferenceObject(targetProcess);

	if (NT_SUCCESS(status))
	{
		__try {
			RtlCopyMemory(bufferAddress, tempBuffer, foundModules * sizeof(KERNEL_MODULE_INFO));
			*moduleCount = foundModules;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { status = STATUS_INVALID_USER_BUFFER; }
	}

	ExFreePoolWithTag(tempBuffer, POOL_TAG_MODS);
	return status;
}