// Relative Path: Driver\ProcessLister.c
#include "NTUndocumented.h"
#include "ProcessLister.h"
#include "Utility.h"

// Helper to define a pool tag for allocations
#define POOL_TAG_PROC 'corP' // "Proc" reversed
#define POOL_TAG_NAME 'emaN' // "Name" reversed
#define POOL_TAG_MODS 'sdoM' // "Mods" reversed

static PSYSTEM_PROCESS_INFORMATION GetRawProcessList()
{
	ULONG bufferSize = 0;
	PVOID bufferPtr = NULL;
	NTSTATUS status;

	// Query required size first
	status = ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &bufferSize);

	// Loop to handle list growth between query and allocation
	do
	{
		// If we have a size, allocate it with some padding to account for new processes created 
		// between the size query and the data query.
		if (bufferSize == 0) break;

		// Add 4KB padding
		bufferSize += 0x1000;

		bufferPtr = ExAllocatePoolWithTag(NonPagedPool, bufferSize, POOL_TAG_PROC);

		if (bufferPtr == NULL)
		{
			return NULL; // Allocation failed
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, bufferPtr, bufferSize, &bufferSize);

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			// Buffer was still too small, free and retry with new size returned by ZwQuery
			ExFreePoolWithTag(bufferPtr, POOL_TAG_PROC);
			bufferPtr = NULL;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(status) && bufferPtr != NULL)
	{
		// If failed for other reasons, cleanup
		ExFreePoolWithTag(bufferPtr, POOL_TAG_PROC);
		return NULL;
	}

	return (PSYSTEM_PROCESS_INFORMATION)bufferPtr;
}

static ULONG CalculateProcessListOutputSize(PSYSTEM_PROCESS_INFORMATION rawProcessList)
{
	int size = 0;

	// Safety check
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

// Helper to check if a module name indicates .NET runtime
static BOOLEAN IsDotNetModule(UNICODE_STRING* dllName)
{
	if (dllName == NULL || dllName->Buffer == NULL) return FALSE;

	// Kernel mode string search
	WCHAR* buffer = dllName->Buffer;
	USHORT len = dllName->Length / sizeof(WCHAR);

	for (USHORT i = 0; i < len; i++)
	{
		// Check for 'clr.'
		if (len - i >= 4)
		{
			if ((buffer[i] == 'c' || buffer[i] == 'C') &&
				(buffer[i + 1] == 'l' || buffer[i + 1] == 'L') &&
				(buffer[i + 2] == 'r' || buffer[i + 2] == 'R') &&
				(buffer[i + 3] == '.'))
			{
				return TRUE;
			}
		}
		// Check for 'mscoree'
		if (len - i >= 7)
		{
			if ((buffer[i] == 'm' || buffer[i] == 'M') &&
				(buffer[i + 1] == 's' || buffer[i + 1] == 'S') &&
				(buffer[i + 2] == 'c' || buffer[i + 2] == 'C') &&
				(buffer[i + 3] == 'o' || buffer[i + 3] == 'O') &&
				(buffer[i + 4] == 'r' || buffer[i + 4] == 'R') &&
				(buffer[i + 5] == 'e' || buffer[i + 5] == 'E') &&
				(buffer[i + 6] == 'e' || buffer[i + 6] == 'E'))
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

static PLDR_DATA_TABLE_ENTRY_PE GetMainModuleDataTableEntry(PPEB64_PE peb, PBOOLEAN isDotNet)
{
	*isDotNet = FALSE;
	PLDR_DATA_TABLE_ENTRY_PE mainEntry = NULL;

	if (SanitizeUserPointer(peb, sizeof(PEB64_PE)))
	{
		if (peb->Ldr)
		{
			if (SanitizeUserPointer(peb->Ldr, sizeof(PEB_LDR_DATA_PE)))
			{
				if (!peb->Ldr->Initialized)
				{
					int initLoadCount = 0;
					while (!peb->Ldr->Initialized && initLoadCount++ < 4)
					{
						DriverSleep(250);
					}
				}

				if (peb->Ldr->Initialized)
				{
					// Get Main Module
					mainEntry = CONTAINING_RECORD(peb->Ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY_PE, InLoadOrderLinks);

					// Scan for .NET modules
					PLIST_ENTRY listHead = &peb->Ldr->InLoadOrderModuleList;
					PLIST_ENTRY current = listHead->Flink;
					int safety = 0;

					while (current != listHead && safety < 500)
					{
						PLDR_DATA_TABLE_ENTRY_PE entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_PE, InLoadOrderLinks);
						if (SanitizeUserPointer(entry, sizeof(LDR_DATA_TABLE_ENTRY_PE)))
						{
							if (IsDotNetModule(&entry->BaseDllName))
							{
								*isDotNet = TRUE;
							}
						}
						current = current->Flink;
						if (!SanitizeUserPointer(current, sizeof(LIST_ENTRY))) break;
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

	if (SanitizeUserPointer(peb, sizeof(PEB32)))
	{
		PPEB_LDR_DATA32 ldr = (PPEB_LDR_DATA32)(ULONG_PTR)peb->Ldr;
		if (SanitizeUserPointer(ldr, sizeof(PEB_LDR_DATA32)))
		{
			if (!ldr->Initialized)
			{
				int initLoadCount = 0;
				while (!ldr->Initialized && initLoadCount++ < 4)
				{
					DriverSleep(250);
				}
			}

			if (ldr->Initialized)
			{
				mainEntry = CONTAINING_RECORD(ldr->InLoadOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

				// Scan for .NET modules
				PLIST_ENTRY32 listHead = &ldr->InLoadOrderModuleList;
				PLIST_ENTRY32 current = (PLIST_ENTRY32)(ULONG_PTR)listHead->Flink;
				int safety = 0;

				while (current != (PLIST_ENTRY32)(ULONG_PTR)listHead && safety < 500)
				{
					PLDR_DATA_TABLE_ENTRY32 entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
					if (SanitizeUserPointer(entry, sizeof(LDR_DATA_TABLE_ENTRY32)))
					{
						// Convert UNICODE_STRING32 to UNICODE_STRING for helper
						UNICODE_STRING tempName;
						tempName.Length = entry->BaseDllName.Length;
						tempName.MaximumLength = entry->BaseDllName.MaximumLength;
						tempName.Buffer = (PWCH)(ULONG_PTR)entry->BaseDllName.Buffer;

						if (IsDotNetModule(&tempName))
						{
							*isDotNet = TRUE;
						}
					}
					current = (PLIST_ENTRY32)(ULONG_PTR)current->Flink;
					if (!SanitizeUserPointer(current, sizeof(LIST_ENTRY32))) break;
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

	// Important: Capture the pointer to free it later, as we might iterate rawProcessList pointer
	PVOID listHeadPointer = rawProcessList;

	*processCount = 0;

	if (rawProcessList)
	{
		int expectedBufferSize = CalculateProcessListOutputSize(rawProcessList);

		if (!listedProcessBuffer || bufferSize < expectedBufferSize)
		{
			*requiredBufferSize = expectedBufferSize;
			// Must free the list before returning
			ExFreePoolWithTag(listHeadPointer, POOL_TAG_PROC);
			return STATUS_INFO_LENGTH_MISMATCH;
		}

		// rawProcessList iterator
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
								// WoW64 Path
								PPEB32 peb = (PPEB32)wow64Process;
								if (peb)
								{
									PLDR_DATA_TABLE_ENTRY32 mainModuleEntry = GetMainModuleDataTableEntry32(peb, &isDotNet);
									mainModuleEntry = SanitizeUserPointer(mainModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY32));

									if (mainModuleEntry)
									{
										mainModuleEntryPoint = (PVOID)(ULONG_PTR)mainModuleEntry->EntryPoint;
										mainModuleImageSize = mainModuleEntry->SizeOfImage;
										isWow64 = TRUE;

										// Use Tagged Allocation
										mainModuleFileName = ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(WCHAR), POOL_TAG_NAME);
										if (mainModuleFileName)
										{
											RtlZeroMemory(mainModuleFileName, 256 * sizeof(WCHAR));

											if (mainModuleEntry->FullDllName.Buffer)
											{
												PWCH src = (PWCH)(ULONG_PTR)mainModuleEntry->FullDllName.Buffer;
												if (SanitizeUserPointer(src, mainModuleEntry->FullDllName.Length))
													RtlCopyMemory(mainModuleFileName, src, mainModuleEntry->FullDllName.Length);
											}
										}
									}
								}
							}
							else
							{
								// Native x64 Path
								PPEB64_PE peb = (PPEB64_PE)PsGetProcessPeb(targetProcess);

								if (peb)
								{
									PLDR_DATA_TABLE_ENTRY_PE mainModuleEntry = GetMainModuleDataTableEntry(peb, &isDotNet);
									mainModuleEntry = SanitizeUserPointer(mainModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY_PE));

									if (mainModuleEntry)
									{
										mainModuleEntryPoint = mainModuleEntry->EntryPoint;
										mainModuleImageSize = mainModuleEntry->SizeOfImage;
										isWow64 = FALSE; // Native

										// Use Tagged Allocation
										mainModuleFileName = ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(WCHAR), POOL_TAG_NAME);
										if (mainModuleFileName)
										{
											RtlZeroMemory(mainModuleFileName, 256 * sizeof(WCHAR));
											if (mainModuleEntry->FullDllName.Buffer)
											{
												if (SanitizeUserPointer(mainModuleEntry->FullDllName.Buffer, mainModuleEntry->FullDllName.Length))
													RtlCopyMemory(mainModuleFileName, mainModuleEntry->FullDllName.Buffer, mainModuleEntry->FullDllName.Length);
											}
										}
									}
								}
							}
						}
					}
					__except (GetExceptionCode())
					{
						DbgPrintEx(0, 0, "Peb Interaction Failed.\n");
					}
				}
				__finally
				{
					KeUnstackDetachProcess(&state);
				}

				if (mainModuleFileName)
				{
					RtlCopyMemory(processSummary->MainModuleFileName, mainModuleFileName, 256 * sizeof(WCHAR));

					// Use Tagged Free
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

		// Use Tagged Free
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

	if (maxModules == 0 || bufferSize > 1024 * 1024 * 10)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Use Tagged Allocation
	tempBuffer = (PKERNEL_MODULE_INFO)ExAllocatePoolWithTag(PagedPool, bufferSize, POOL_TAG_MODS);
	if (!tempBuffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(tempBuffer, bufferSize);

	status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetProcessId, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(tempBuffer, POOL_TAG_MODS);
		return status;
	}

	KeStackAttachProcess(targetProcess, &state);

	// 1. PEB Walking (Standard Modules)
	__try
	{
		PVOID wow64Process = PsGetProcessWow64Process(targetProcess);

		if (wow64Process != NULL)
		{
			PPEB32 peb32 = (PPEB32)wow64Process;
			if (SanitizeUserPointer(peb32, sizeof(PEB32)))
			{
				PPEB_LDR_DATA32 ldr32 = (PPEB_LDR_DATA32)(ULONG_PTR)peb32->Ldr;
				if (SanitizeUserPointer(ldr32, sizeof(PEB_LDR_DATA32)))
				{
					PLIST_ENTRY32 listHead = &ldr32->InLoadOrderModuleList;
					PLIST_ENTRY32 current = (PLIST_ENTRY32)(ULONG_PTR)listHead->Flink;

					while (current != listHead && foundModules < maxModules)
					{
						PLDR_DATA_TABLE_ENTRY32 entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
						if (SanitizeUserPointer(entry, sizeof(LDR_DATA_TABLE_ENTRY32)))
						{
							if (entry->DllBase != 0)
							{
								tempBuffer[foundModules].BaseAddress = (PVOID)(ULONG_PTR)entry->DllBase;
								tempBuffer[foundModules].SizeOfImage = entry->SizeOfImage;
								if (entry->FullDllName.Buffer != 0 && entry->FullDllName.Length > 0)
								{
									PWCHAR srcName = (PWCHAR)(ULONG_PTR)entry->FullDllName.Buffer;
									if (SanitizeUserPointer(srcName, entry->FullDllName.Length))
									{
										USHORT copyLen = entry->FullDllName.Length;
										if (copyLen > sizeof(tempBuffer[0].FullPathName) - sizeof(WCHAR))
											copyLen = sizeof(tempBuffer[0].FullPathName) - sizeof(WCHAR);
										RtlCopyMemory(tempBuffer[foundModules].FullPathName, srcName, copyLen);
									}
								}
								foundModules++;
							}
						}
						current = (PLIST_ENTRY32)(ULONG_PTR)current->Flink;
						if (!SanitizeUserPointer(current, sizeof(LIST_ENTRY32))) break;
					}
				}
			}
		}
		else
		{
			PPEB peb = PsGetProcessPeb(targetProcess);
			if (SanitizeUserPointer(peb, sizeof(PEB)))
			{
				PPEB_LDR_DATA ldr = peb->Ldr;
				if (SanitizeUserPointer(ldr, sizeof(PEB_LDR_DATA)))
				{
					PLIST_ENTRY listHead = &ldr->InLoadOrderModuleList;
					PLIST_ENTRY current = listHead->Flink;
					while (current != listHead && foundModules < maxModules)
					{
						PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
						if (SanitizeUserPointer(entry, sizeof(LDR_DATA_TABLE_ENTRY)))
						{
							if (entry->DllBase != NULL)
							{
								tempBuffer[foundModules].BaseAddress = entry->DllBase;
								tempBuffer[foundModules].SizeOfImage = entry->SizeOfImage;
								if (entry->FullDllName.Buffer != NULL && entry->FullDllName.Length > 0)
								{
									if (SanitizeUserPointer(entry->FullDllName.Buffer, entry->FullDllName.Length))
									{
										USHORT copyLen = entry->FullDllName.Length;
										if (copyLen > sizeof(tempBuffer[0].FullPathName) - sizeof(WCHAR))
											copyLen = sizeof(tempBuffer[0].FullPathName) - sizeof(WCHAR);
										RtlCopyMemory(tempBuffer[foundModules].FullPathName, entry->FullDllName.Buffer, copyLen);
									}
								}
								foundModules++;
							}
						}
						current = current->Flink;
						if (!SanitizeUserPointer(current, sizeof(LIST_ENTRY))) break;
					}
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception during PEB walk\n");
	}

	// 2. Manual Map Detection (Memory Scanning)
	__try
	{
		PVOID baseAddr = (PVOID)0;
		MEMORY_BASIC_INFORMATION memInfo;

		// ZwQueryVirtualMemory on the current process (which is the TARGET process context due to KeStackAttachProcess)
		while (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), baseAddr, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), NULL)))
		{
			// Filter for executable regions that are committed
			if ((memInfo.State & MEM_COMMIT) &&
				(memInfo.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
			{
				BOOLEAN alreadyFound = FALSE;
				for (ULONG i = 0; i < foundModules; i++)
				{
					if (tempBuffer[i].BaseAddress == memInfo.BaseAddress || tempBuffer[i].BaseAddress == memInfo.AllocationBase)
					{
						alreadyFound = TRUE;
						break;
					}
				}

				if (!alreadyFound && foundModules < maxModules)
				{
					tempBuffer[foundModules].BaseAddress = memInfo.BaseAddress;
					tempBuffer[foundModules].SizeOfImage = (ULONG)memInfo.RegionSize;

					WCHAR manualName[] = L"ManualMap_Region";
					RtlCopyMemory(tempBuffer[foundModules].FullPathName, manualName, sizeof(manualName));

					foundModules++;
				}
			}

			// Move to next region
			PVOID nextAddr = (PVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);

			// Check for overflow/wrap-around
			if (nextAddr <= baseAddr) break;
			baseAddr = nextAddr;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KsDumper: Exception during Memory Scan\n");
	}

	KeUnstackDetachProcess(&state);
	ObDereferenceObject(targetProcess);

	if (NT_SUCCESS(status))
	{
		__try
		{
			RtlCopyMemory(bufferAddress, tempBuffer, foundModules * sizeof(KERNEL_MODULE_INFO));
			*moduleCount = foundModules;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = STATUS_INVALID_USER_BUFFER;
		}
	}

	ExFreePoolWithTag(tempBuffer, POOL_TAG_MODS);
	return status;
}