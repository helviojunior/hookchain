//===============================================================================================//
#ifndef _OKCHAIN_OK_H
#define _OKCHAIN_OK_H
//===============================================================================================//

#include <Windows.h>
#include "windows_common.h"

#define DEBUG
//#undef DEBUG

#define MAX_ENTRIES 512
#define PREV -32
#define NEXT 32
#define MAX_NEIGHBOURS 500

typedef struct _SYSCALL_INFO {
	DWORD64 dwSsn;
	PVOID pAddress;
	PVOID pSyscallRet;
	PVOID pStubFunction;
	DWORD64 dwHash;
	BOOL bIsHooked;
} SYSCALL_INFO, * PSYSCALL_INFO;

typedef struct _SYSCALL_LIST
{
	DWORD64 Count;
	SYSCALL_INFO Entries[MAX_ENTRIES];
} SYSCALL_LIST, * PSYSCALL_LIST;

typedef struct _FUNCTION_CODE {
	BYTE     Buffer[40];
} FUNCTION_CODE, * PFUNCTION_CODE;

typedef struct _MODULE_INFO {
	PVOID pAddress;
	DWORD64 dwHash;
} MODULE_INFO, * PMODULE_INFO;

typedef struct _MODULE_LIST
{
	DWORD64 Count;
	MODULE_INFO Entries[MAX_ENTRIES];
} MODULE_LIST, * PMODULE_LIST;

typedef struct _FUNCTION_NAME {
	BYTE     Buffer[255];
} FUNCTION_NAME, * PFUNCTION_NAME;

typedef struct _NAME_LIST
{
	DWORD64 Count;
	FUNCTION_NAME Entries[50];
} NAME_LIST, * PNAME_LIST;



static PVOID GetNextSyscallInstruction(_In_ PVOID pStartAddr);
static DWORD64 GetSSN(_In_ PVOID pAddress);
FARPROC HGetModuleHandleA(LPCSTR imageName, _In_ BOOLEAN forceLoad);
FARPROC HGetProcAddress(LPCSTR imageName, LPCSTR procName);
FARPROC HGetProcAddress3(FARPROC imageBase, LPCSTR procName);
BOOL UnhookAll(_In_ HANDLE hProcess, _In_ LPCSTR imageName, _In_ BOOLEAN force);
BOOL ProcAllByAddr(_In_ LPCSTR imageBaseName, _In_ PVOID imageBase, _In_opt_ HANDLE hProcess);
PVOID GetClearNtdll(VOID);

BOOL GetBaseAddresses(VOID);
BOOL InitApi(VOID);
DWORD64 djb2(PBYTE str);

typedef VOID(*PPS_APC_ROUTINE)(PVOID SystemArgument1, PVOID SystemArgument2, PVOID SystemArgument3, PCONTEXT ContextRecord);

NTSTATUS NtAllocateReserveObject(_Out_ PHANDLE MemoryReserveHandle, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ MEMORY_RESERVE_OBJECT_TYPE ObjectType);
NTSTATUS NtAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect);
NTSTATUS NtCreateProcessEx(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ParentProcess, _In_ ULONG Flags, _In_opt_ HANDLE SectionHandle, _In_opt_ HANDLE DebugPort, _In_opt_ HANDLE ExceptionPort, _In_ BOOLEAN InJob);
NTSTATUS NtCreateThreadEx(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle, _In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags, _In_opt_ ULONG_PTR ZeroBits, _In_opt_ SIZE_T StackSize, _In_opt_ SIZE_T MaximumStackSize, _In_opt_ PVOID AttributeList);
NTSTATUS NtOpenProcess(_Out_ PHANDLE ProcessHandle, _In_ ACCESS_MASK AccessMask, _In_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ PCLIENT_ID ClientId);
NTSTATUS NtQueryInformationProcess(_In_ HANDLE ProcessHandle, _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass, _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
NTSTATUS NtQueueApcThreadEx(_In_ HANDLE ThreadHandle, _In_ HANDLE UserApcReserveHandle, _In_ PPS_APC_ROUTINE ApcRoutine, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2, _In_opt_ PVOID SystemArgument3);
NTSTATUS NtProtectVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection);
NTSTATUS NtReadVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _Out_ PVOID Buffer, _In_ ULONG NumberOfBytesToRead, _Out_opt_ PULONG NumberOfBytesReaded);
NTSTATUS NtResumeThread(_In_ HANDLE ThreadHandle, _Out_opt_ PULONG SuspendCount);
NTSTATUS NtWaitForSingleObject(_In_ HANDLE ObjectHandle, _In_ BOOLEAN Alertable OPTIONAL, _In_ PLARGE_INTEGER TimeOut);
NTSTATUS NtWriteVirtualMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ PVOID Buffer, _In_ ULONG NumberOfBytesToWrite, _Out_opt_ PULONG NumberOfBytesWritten);

BOOL HReadProcessMemory(_In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _Out_ PVOID Buffer, _In_ ULONG NumberOfBytesToRead, _Out_opt_ PULONG NumberOfBytesReaded);
BOOL HVirtualProtect(_Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection);
BOOL HVirtualProtectEx(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _Inout_ PULONG NumberOfBytesToProtect, _In_ ULONG NewAccessProtection, _Out_ PULONG OldAccessProtection);
SIZE_T HVirtualQuery(_In_ PVOID lpAddress, _Out_ PVOID lpBuffer, _In_ ULONG dwLength);
SIZE_T HVirtualQueryEx(_In_ HANDLE hProcess, _In_ PVOID lpAddress, _Out_ PVOID lpBuffer, _In_ ULONG dwLength);

// Local defs

DWORD InitSyscallInfo(PSYSCALL_INFO pSyscallInfo, PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD64 dwHash);
ULONG InjectMemory(HANDLE ProcessHandle, PVOID DestinationAddress, ULONG NumberOfBytesToWrite);
PVOID GetReflectiveLoader(PVOID pModuleBase);
PVOID RtlAllocateHeapStub(_In_ PVOID  HeapHandle, _In_ ULONG  Flags, _In_ SIZE_T Size);

static PVOID pRtlAllocateHeap;
static PVOID pUn;
#if _WIN64
#define NtCurrentTeb()            ((PTEB)__readgsqword(0x30))
#else
#define NtCurrentTeb()            ((PTEB)__readfsdword(0x16))
#endif

#define NtCurrentPeb()            (NtCurrentTeb()->ProcessEnvironmentBlock)
#define RtlProcessHeap()          (NtCurrentPeb()->ProcessHeap)

#define Local()					  ((HANDLE)-1)

//===============================================================================================//
#endif
//===============================================================================================//
