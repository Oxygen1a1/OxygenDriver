#pragma once

#include "Global.h"

bool WriteByMdl(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, size_t BufferLength, PULONG ReturnLength OPTIONAL);

namespace ReadWrite {
	
	//头文件导出
	
	NTSTATUS MyWriteMem(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, size_t BufferLength, PULONG ReturnLength OPTIONAL);
	NTSTATUS MyAllocMem(HANDLE ProcessId, PVOID* pLpAddress, INT64 ZeroBits, SIZE_T* pSize, DWORD32 flAllocationType, DWORD32 flProtect, ULONG_PTR* lpAllocAddr);
	NTSTATUS MyProtectMem(HANDLE ProcessId, PVOID* plpAddress, SIZE_T* pSize_t, DWORD32 dwNewProtect, PDWORD32 OldProtect);
	NTSTATUS MyReadMem(IN HANDLE ProcessId, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL);
	NTSTATUS MyCreateThread(HANDLE ProcessId, UINT64 lpStartAddress, UINT64 lParam, DWORD32 CreateFlags, UINT64 StackSize, OUT PHANDLE hThread);
	void ChangePreviousMode();
	void ResumePreviousMode();


}