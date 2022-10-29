#include <Windows.h>
#include "EzPdb/EzPdb.h"
#include "Global.h"
#include <windef.h>

int main() {

	
		std::string kernel = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
		std::string pdbPath = EzPdbDownload(kernel);
		if (pdbPath.empty())
		{
			std::cout << "download pdb failed " << GetLastError() << std::endl;;
			return 1;
		}

		
		EZPDB pdb;
		if (!EzPdbLoad(pdbPath, &pdb))
		{
			std::cout << "load pdb failed " << GetLastError() << std::endl;
			return 1;
		}


		InitPdb Init;

		Init.uPspNotifyEnableMaskRva = (ULONG_PTR)EzPdbGetRva(&pdb,"PspNotifyEnableMask");
		Init.uRvaNtAlloc=(ULONG_PTR)EzPdbGetRva(&pdb, "NtAllocateVirtualMemory");
		Init.uRvaNtCreateThread = (ULONG_PTR)EzPdbGetRva(&pdb, "NtCreateThreadEx");
		Init.uRvaNtProtect = (ULONG_PTR)EzPdbGetRva(&pdb, "NtProtectVirtualMemory");
		Init.uRvaNtRead = (ULONG_PTR)EzPdbGetRva(&pdb, "NtReadVirtualMemory");
		Init.uRvaNtWrite = (ULONG_PTR)EzPdbGetRva(&pdb, "NtWriteVirtualMemory");
		Init.uVadRoot = (ULONG_PTR)EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"VadRoot");
		Init.uThreadPreviouMode = (ULONG_PTR)EzPdbGetStructPropertyOffset(&pdb, "_KTHREAD", L"PreviousMode");
		Init.uApcState = (ULONG_PTR)EzPdbGetStructPropertyOffset(&pdb, "_KTHREAD", L"ApcStateFill");
		Init.uUserApcPendingAll = (ULONG_PTR)EzPdbGetStructPropertyOffset(&pdb, "_KAPC_STATE", L"UserApcPendingAll");
		Init.pGetProcAddress = (ULONG_PTR)GetProcAddress;
		Init.pLoadLibraryA = (ULONG_PTR)LoadLibraryA;
		Init.pRtlAddFunctionTable = (ULONG_PTR)RtlAddFunctionTable;


		HANDLE hFile=CreateFile(L"\\\\.\\OxygenDriver", GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, nullptr);

		if (hFile == INVALID_HANDLE_VALUE) {
			printf("打开失败\n");
			getchar();
			return -1;
		}

		//初始化

		BOOL bOk=DeviceIoControl(hFile, CTL_CODE_INIT, &Init, sizeof(InitPdb), &Init, sizeof(InitPdb), 0, 0);

		if (!bOk) {

			printf("初始化失败\n");

			getchar();
			return -2;

		}

		EzPdbUnload(&pdb);

		system("pause");

		return 0;
	

	

}