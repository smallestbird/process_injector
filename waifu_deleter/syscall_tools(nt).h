#pragma once
#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <ios>
#include <processthreadsapi.h>

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }


VOID IndirectPrelude(
	_In_  HMODULE NtdllHandle,
	_In_  LPCSTR NtFunctionName,
	_Out_ PDWORD NtFunctionSSN,
	_Out_ PUINT_PTR NtFunctionSyscall
);

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;                                                           //0x0
	VOID* RootDirectory;                                                    //0x8
	struct _UNICODE_STRING* ObjectName;                                     //0x10
	ULONG Attributes;                                                       //0x18
	VOID* SecurityDescriptor;                                               //0x20
	VOID* SecurityQualityOfService;                                         //0x28
}OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	VOID* UniqueProcess;                                                    //0x0
	VOID* UniqueThread;                                                     //0x8
}CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

//nt function


extern "C" {
	typedef unsigned __int64 QWORD;
	DWORD g_NtOpenProcessSSN;
	QWORD g_NtOpenProcessSyscall;
	DWORD g_NtAllocateVirtualMemorySSN;
	QWORD g_NtAllocateVirtualMemorySyscall;
	DWORD g_NtWriteVirtualMemorySSN;
	QWORD g_NtWriteVirtualMemorySyscall;
	DWORD g_NtProtectVirtualMemorySSN;
	QWORD g_NtProtectVirtualMemorySyscall;
	DWORD g_NtCreateThreadExSSN;
	QWORD g_NtCreateThreadExSyscall;
	DWORD g_NtWaitForSingleObjectSSN;
	QWORD g_NtWaitForSingleObjectSyscall;
	DWORD g_NtCloseSSN;
	QWORD g_NtCloseSyscall;
	


	extern NTSTATUS NTAPI NtOpenProcess(
		_Out_ PHANDLE ProcessHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PCLIENT_ID ClientId
	);

	extern NTSTATUS NTAPI NtAllocateVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
		_In_ ULONG_PTR ZeroBits,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG AllocationType,
		_In_ ULONG Protect
	);
	extern NTSTATUS NTAPI NtWriteVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PVOID BaseAddress,
		_In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
		_In_ SIZE_T NumberOfBytesToWrite,
		_Out_opt_ PSIZE_T NumberOfBytesWritten
	);
	extern NTSTATUS NTAPI NtCreateThreadEx(
		_Out_ PHANDLE ThreadHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_ HANDLE ProcessHandle,
		_In_ PVOID StartRoutine,
		_In_opt_ PVOID Argument,
		_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
		_In_ SIZE_T ZeroBits,
		_In_ SIZE_T StackSize,
		_In_ SIZE_T MaximumStackSize,
		_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
	);

	extern NTSTATUS NTAPI NtClose(
		_In_ _Post_ptr_invalid_ HANDLE Handle
	);
	extern NTSTATUS NTAPI NtWaitForSingleObject(
		_In_ HANDLE Handle,
		_In_ BOOLEAN Alertable,
		_In_opt_ PLARGE_INTEGER Timeout
	);
	extern NTSTATUS NTAPI NtProtectVirtualMemory(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG NewProtection,
		_Out_ PULONG OldProtection
	);
	
}


