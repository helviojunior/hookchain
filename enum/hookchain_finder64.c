// HookChain: Hook Finder
// Compiling gcc .\hookchain_finder64.c -o .\hookchain_finder64.exe
//

#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <dbghelp.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <winnt.h>
#pragma comment (lib, "dbghelp.lib")

#define MAX_NAME 255
#define MAX_ENTRIES 1024

typedef struct _ENTRY_INFO {
    PVOID Address;
    PCHAR Name;
    BOOL IsHooked;
} ENTRY_INFO, * PENTRY_INFO;

typedef struct _NT_LIST
{
    long Count;
    ENTRY_INFO Entries[MAX_ENTRIES];
} NT_LIST, * PNT_LIST;

static NT_LIST NtlList;

BOOL FillNtList();
VOID CheckDll(CHAR *name, HANDLE baseAddress);
VOID DumpListOfHookedDlls();
BOOL CheckHook(CHAR *callerName, CHAR *libraryName, CHAR *functionName, DWORD64 functionAddress);
VOID ListLoadedDlls();

typedef struct _CPEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBase;
    PPEB_LDR_DATA           LoaderData;
    PVOID                   ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PVOID                   FastPebLockRoutine;
    PVOID                   FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PVOID                   FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID** ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} CPEB, * PCPEB;

BOOL FillNtList() {

    printf("[+] Listing ntdll Nt/Zw functions\n------------------------------------------\n");

    PTEB pCurrentTeb;
    PCPEB pCurrentPeb;

    PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;

    PVOID pBase;

#if _WIN64
    pCurrentTeb = (PTEB)__readgsqword(0x30);
#else
    pCurrentTeb = (PTEB)__readfsdword(0x16);
#endif

    pCurrentPeb = (PCPEB)pCurrentTeb->ProcessEnvironmentBlock;

    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0x0a)
        return FALSE;

    pImageExportDirectory = NULL;
    pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    pBase = pLdrDataEntry->DllBase;

    pImageDosHeader = (PIMAGE_DOS_HEADER)pBase;

    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pImageDosHeader->e_lfanew);

    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)pBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress
        );

    PDWORD pdwFunctions;
    PDWORD pdwNames;
    PWORD pwNameOrdinals;

    PDWORD pcName = NULL;
    PVOID pAddress = NULL;

    pdwFunctions = (PDWORD)((PBYTE)pBase + pImageExportDirectory->AddressOfFunctions);
    pdwNames = (PDWORD)((PBYTE)pBase + pImageExportDirectory->AddressOfNames);
    pwNameOrdinals = (PWORD)((PBYTE)pBase + pImageExportDirectory->AddressOfNameOrdinals);

    PENTRY_INFO Entries = NtlList.Entries;
    DWORD idx = 0;

    for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
        pcName = (PDWORD)((PBYTE)pBase + pdwNames[i]);
        pAddress = (PBYTE)pBase + pdwFunctions[pwNameOrdinals[i]];

        if ((*(USHORT*)pcName != 'tN') && (*(USHORT*)pcName != 'wZ'))
            continue;

        BOOLEAN dupFound = FALSE;
        for (DWORD id = 0; id < idx; id++)
        {
            if ((DWORD64)Entries[id].Address == (DWORD64)pAddress)
                dupFound = TRUE;
        }

        if (dupFound)
            continue;

        Entries[idx].Address = pAddress;
        Entries[idx].Name = (PCHAR)pcName;
        Entries[idx].IsHooked = FALSE;
        if (*((PBYTE)pAddress) == 0xe9 || *((PBYTE)pAddress + 3) == 0xe9) Entries[idx].IsHooked = TRUE;

        if (Entries[idx].IsHooked) printf("%s is hooked\n", pcName);

        printf("   ntdll[%d] %s 0x%p\n", idx, pcName, pAddress);

        idx++;
        if (idx == MAX_ENTRIES) break;
    }

    // Save total number of system calls found.
    NtlList.Count = idx;

    printf("Mapped %d functions\n\n", NtlList.Count);

    return TRUE;
}

VOID CheckDll(CHAR *name, HANDLE imageBase) {

    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
    HMODULE library = NULL;
    LPCSTR libraryName = NULL;
    
    pImageDosHeader = (PIMAGE_DOS_HEADER)imageBase;

    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + pImageDosHeader->e_lfanew);

    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return;

    pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)imageBase + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDescriptor->Name != 0x00) {
        
        //Get name of the DLL in the Import Table
        libraryName = (LPCSTR)((PBYTE)imageBase + pImportDescriptor->Name);
        if ((libraryName) && (_stricmp(libraryName, "ntdll.dll") == 0)) {
            library = GetModuleHandleA(libraryName);
            if (library) {

                DWORD cnt = 0;

                printf("Checking %s at %s IAT\n", libraryName, name);
                
                //Get Import Lookup Table (OriginalFirstThunk) and Import Address Table (FirstThunk)
                PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;

                firstThunk = (PIMAGE_THUNK_DATA) ((PBYTE) imageBase + pImportDescriptor->FirstThunk);
                originalFirstThunk = (PIMAGE_THUNK_DATA) ((PBYTE) imageBase + pImportDescriptor->OriginalFirstThunk);
                PIMAGE_IMPORT_BY_NAME function = NULL; 

                while ((originalFirstThunk->u1.AddressOfData != NULL) && ((originalFirstThunk->u1.AddressOfData & 0xffffffffffff) >= 0x1000)){
                    
                    function = (PIMAGE_IMPORT_BY_NAME)((PBYTE)imageBase + originalFirstThunk->u1.AddressOfData);

                    if (CheckHook(name, (char *)libraryName, function->Name, (DWORD64)firstThunk->u1.Function)) cnt++;
                
                    ++originalFirstThunk;
                    ++firstThunk;

                }

                printf("  +-- %d hooked functions.\n\n", cnt);

            }
        }
        pImportDescriptor++;
    }
}

BOOL CheckHook(CHAR *callerName, CHAR *libraryName, CHAR *functionName, DWORD64 functionAddress) {

    BOOL hooked = FALSE;
    char * ntHoked = "";

    PENTRY_INFO Entries = NtlList.Entries;
    for (DWORD i = 0; i < NtlList.Count - 1; i++)
    {
        if (_stricmp(functionName, Entries[i].Name) == 0)
            printf("%s %s 0x%p, 0x%p\n", functionName, Entries[i].Name, (DWORD64)Entries[i].Address, functionAddress);

        if ((_stricmp(functionName, Entries[i].Name) == 0) && (strlen(functionName) == strlen(Entries[i].Name)) && ((DWORD64)Entries[i].Address != functionAddress))
        {
            hooked = TRUE;
            if (Entries[i].IsHooked) ntHoked = "*";
            break;
        }
    }

    if (hooked) printf("  |-- %s IAT to %s of function %s%s is hooked to 0x%p\n", callerName, libraryName, ntHoked, functionName, functionAddress);

    return hooked;
}

VOID DumpListOfHookedDlls() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    printf("[+] Listing hooked modules\n------------------------------------------\n");
    if(Module32First(hSnap, &me32)) {
        do {
            //printf("%s is loaded at 0x%p.\n", me32.szExePath, me32.modBaseAddr);
            CheckDll((CHAR *)&me32.szModule, me32.modBaseAddr);

        } while(Module32Next(hSnap, &me32));
    }

    CloseHandle(hSnap);
}

VOID ListLoadedDlls() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    printf("[+] Listing loaded modules\n------------------------------------------\n");
    if(Module32First(hSnap, &me32)) {
        do {
            printf("%s is loaded at 0x%p.\n", me32.szExePath, me32.modBaseAddr);

        } while(Module32Next(hSnap, &me32));
    }

    printf("\n");
    CloseHandle(hSnap);
}

int main (int argc, char **argv) {
    printf("HookChainFinder M4v3r1ck by Sec4US Team\n\n");

    if (!FillNtList()) {
        printf("[-] Error getting NT... list\n");
        ExitProcess(1);
    }

printf("[*] Press enter to continue...");  getchar();

    if ( argc > 1 ) {
        CHAR *dll = argv[1];
        HANDLE hDll = LoadLibrary(dll);

        printf("[+] Loading DLL %s\n------------------------------------------\n", dll);
        if(hDll == NULL) {
            printf("[-] Error loading DLL\n\n");
        }else{
            printf("%s is loaded at 0x%p.\n\n", dll, hDll);
        }
        CloseHandle(hDll);
    }

    ListLoadedDlls();

    DumpListOfHookedDlls();

    printf("------------------------------------------\nCompleted\n");

    return 0;
}
