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

		HMODULE hDll = LoadLibraryA("ntdll.dll");


		InitPdb Init;

		Init.fLdrInitializeThunk = (ULONG_PTR)GetProcAddress(hDll, "LdrInitializeThunk");
		Init.fRtlRaiseStatus = (ULONG_PTR)GetProcAddress(hDll, "RtlRaiseStatus");
		Init.fZwContinue = (ULONG_PTR)GetProcAddress(hDll, "ZwContinue");
		Init.uPspNotifyEnableMaskRva = (ULONG_PTR)EzPdbGetRva(&pdb,"PspNotifyEnableMask");
		Init.uRvaNtAlloc=(ULONG_PTR)EzPdbGetRva(&pdb, "NtAllocateVirtualMemory");
		Init.uRvaNtCreateThread = (ULONG_PTR)EzPdbGetRva(&pdb, "NtCreateThreadEx");
		Init.uRvaNtProtect = (ULONG_PTR)EzPdbGetRva(&pdb, "NtProtectVirtualMemory");
		Init.uRvaNtRead = (ULONG_PTR)EzPdbGetRva(&pdb, "NtReadVirtualMemory");
		Init.uRvaNtWrite = (ULONG_PTR)EzPdbGetRva(&pdb, "NtWriteVirtualMemory");
		Init.uRvaMmpfndatabase = (ULONG_PTR)EzPdbGetRva(&pdb, "MmPfnDatabase");
		Init.uVadRoot = (ULONG_PTR)EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"VadRoot");
		Init.uThreadPreviouMode = (ULONG_PTR)EzPdbGetStructPropertyOffset(&pdb, "_KTHREAD", L"PreviousMode");
		Init.uApcState = (ULONG_PTR)EzPdbGetStructPropertyOffset(&pdb, "_KTHREAD", L"ApcStateFill");
		Init.uOriginPte = (ULONG_PTR)EzPdbGetStructPropertyOffset(&pdb, "_MMPFN", L"OriginalPte");
		Init.uUserApcPendingAll = (ULONG_PTR)EzPdbGetStructPropertyOffset(&pdb, "_KAPC_STATE", L"UserApcPendingAll");
		Init.pGetProcAddress = (ULONG_PTR)GetProcAddress;
		Init.pLoadLibraryA = (ULONG_PTR)LoadLibraryA;
		Init.pRtlAddFunctionTable = (ULONG_PTR)RtlAddFunctionTable;
		Init.pKeServiceDescriptorTable = (ULONG_PTR)EzPdbGetRva(&pdb, "KeServiceDescriptorTable");

		//计算LdrInitializeThunk的第一个Call

		for (ULONG_PTR uIndex = Init.fLdrInitializeThunk;uIndex<Init.fLdrInitializeThunk+0x100; uIndex++) {

			if (*(unsigned char*)uIndex == 0xe8) {

				unsigned long offset = *(unsigned long*)(uIndex + 1);

				//addr
				Init.uLdrFirstCall = (ULONG_PTR)(uIndex + 5 + offset);

				break;
			}


		}




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