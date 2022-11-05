#include "Injector.h"
#include "Global.h"
#include "ReadWrite.h"
#include "PageAttrHide.h"


using namespace Injector_x64;

//方便释放
#define MEM_DLL_TAGS 0x5556

//Dll映射的内存
PVOID g_pMemDll;

//去除ACE对于R3 的Hook
ULONG_PTR  BanACELdrInitializeThunkHook(HANDLE ProcessId, char* OriBytes);


//用于Dll重定位的ShellCode
void __stdcall ShellCode(Manual_Mapping_data* pData);
BOOLEAN MmMapDll(HANDLE ProcessId, PVOID pFileData, UINT64 FileSize,BOOLEAN bPassAce);

BOOLEAN Injector_x64::MmInjector_x64_BypassProtect(HANDLE ProcessId,const wchar_t* wszDllPath,BOOLEAN bPassAce) {
	
	UNREFERENCED_PARAMETER(wszDllPath);
	UNREFERENCED_PARAMETER(ProcessId);


	HANDLE	hFile = 0;
	OBJECT_ATTRIBUTES	objattr;
	NTSTATUS	status=STATUS_SUCCESS;
	//因为穿的参数都是0环地址 所以要改一下PreviousMode

#pragma warning(disable : 4267)

	UNICODE_STRING		usR0DllPath = { 0 };

	usR0DllPath.Buffer = (PWCH)wszDllPath;

	usR0DllPath.Length = wcslen(wszDllPath)*2;

	usR0DllPath.MaximumLength = usR0DllPath.Length;

	//DbgBreakPoint();

	IO_STATUS_BLOCK		IoStatusBlock = { 0 };
	LARGE_INTEGER		lainter = { 0 };
	FILE_STANDARD_INFORMATION	fileinfo = {0};
	UINT64 FileSize=0;
	//初始化Attributes
	InitializeObjectAttributes(&objattr,&usR0DllPath,0x40,0,0);

	

	ReadWrite::ChangePreviousMode();//修改PreviosuMode


	status = NtCreateFile(&hFile, GENERIC_WRITE | GENERIC_READ, &objattr, &IoStatusBlock, &lainter, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, 0, 0);
	
	
	//NtReadFile()

	if (!NT_SUCCESS(status)) {

		//err

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to create file\r\n");


		ReadWrite::ResumePreviousMode();

		return false;
	}



	status=NtQueryInformationFile(hFile, &IoStatusBlock, &fileinfo,sizeof(fileinfo), FileStandardInformation);

	FileSize = fileinfo.AllocationSize.QuadPart;

	if (!NT_SUCCESS(status)) {

		//err

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to query file\r\n");


		ReadWrite::ResumePreviousMode();

		return false;
	}
	
#pragma warning(disable : 4244)
	KdPrint(("[OxygenDriver]file size:0x%x\r\n", FileSize));

	FileSize += 0x1000;

	FileSize &= 0xfffffffffffff000;

	g_pMemDll=ExAllocatePoolWithTag(NonPagedPool, FileSize, MEM_DLL_TAGS);

	

	

	memset(g_pMemDll, 0, fileinfo.AllocationSize.QuadPart);

	LARGE_INTEGER byteoffset = { 0 };


	status = NtReadFile(hFile, 0, 0, 0, &IoStatusBlock, g_pMemDll, FileSize,&byteoffset, 0);

	//刷新一下 不然要等待
	ZwFlushBuffersFile(hFile, &IoStatusBlock);

	if (!NT_SUCCESS(status)) {

		//err

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to read file\r\n");


		ExFreePool(g_pMemDll);

		ReadWrite::ResumePreviousMode();
		return false;

	}

	ReadWrite::ResumePreviousMode();


	

	if (!MmMapDll(ProcessId, g_pMemDll, FileSize,bPassAce)) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to Mm map dll\r\n");

		return 0;
	}


	ExFreePool(g_pMemDll);

	//NtClose(hFile);

	return true;
}

//BOOLEAN Injector::MemInject_PassTp_x64(HANDLE ProcessId, const wchar_t* wszDllPath) {
//
//
//
//
//
//
//	return TRUE;
//
//}
//
//BOOLEAN Injector::MmInject_PassTp_x86(HANDLE ProcessId, const wchar_t* wszDllPath)
//{
//
//	return TRUE;
//}
//
//BOOLEAN Injector::MmInject_PsssBe_x64(HANDLE ProcessId, const wchar_t* wszDllPath)
//{
//	return TRUE;
//}
//



//this func aim to Map a section to process,and relocate
BOOLEAN MmMapDll(HANDLE ProcessId, PVOID pFileData, UINT64 FileSize,BOOLEAN bPassAce) {
	UNREFERENCED_PARAMETER(FileSize);

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOptHeader = nullptr;
	IMAGE_FILE_HEADER* pFileHeader = nullptr;
	NTSTATUS status=STATUS_SUCCESS;

	//开始Map的地址
	char* pStartMapAddr = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pFileData)->e_magic != 0x5A4D) {

		//MZ DOS Head
		DbgPrintEx(77, 0, "[OxygenDriver]err:Unvalid Pe file!\r\n");
		return 0;

	}

	pNtHeader = (IMAGE_NT_HEADERS*)((ULONG_PTR)pFileData + reinterpret_cast<IMAGE_DOS_HEADER*>(pFileData)->e_lfanew);
	pFileHeader = &pNtHeader->FileHeader;
	pOptHeader = &pNtHeader->OptionalHeader;

	if (pFileHeader->Machine != X64) {
		//不是x64文件

		DbgPrintEx(77, 0, "[OxygenDriver]err:File archtrue not match\r\n");

		return 0;

	}


	size_t size = (size_t)pOptHeader->SizeOfImage;

	status=ReadWrite::MyAllocMem(ProcessId,(PVOID*)&pStartMapAddr,0,&size,MEM_COMMIT, PAGE_EXECUTE_READWRITE,0);

	//修改原型PTE 规避检查

	PageAttrHide::ChangeVadAttributes((ULONG_PTR)pStartMapAddr, MM_READONLY,ProcessId);

	if (!NT_SUCCESS(status)) {

		//分配失败

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to alloc mem\r\n");

		return 0;
	}

	//创建Mem_Map_Dll结构体

	Manual_Mapping_data* ManualMapData=(Manual_Mapping_data*)ExAllocatePoolWithTag(NonPagedPool,sizeof(ManualMapData)+2,'MMD');

	ManualMapData->dwReadson = 0;
	ManualMapData->pGetProcAddress = (f_GetProcAddress)Global::GetInstance()->pGetProcAddress;
	ManualMapData->pLoadLibraryA = (f_LoadLibraryA)Global::GetInstance()->pLoadLibraryA;
	ManualMapData->pBase = pStartMapAddr;
	ManualMapData->reservedParam = 0;
	ManualMapData->pRtlAddFunctionTable = (f_RtlAddFunctionTable)Global::GetInstance()->pRtlAddFunctionTable;



	//开始写入PE文件结构

	//写入PE头

	if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pStartMapAddr, pFileData, 0x1000, 0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to Write PE head\r\n");

		return 0;
	}

	//写入PE结构的各节区

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	//因为Section紧密排列 所以可以直接++
	//VirtualAddress=RVA PointerToRawData==FOA
	for (int i = 0; i < pFileHeader->NumberOfSections; i++,pSectionHeader++) {
		
		if (pSectionHeader->SizeOfRawData) {
			if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pStartMapAddr + pSectionHeader->VirtualAddress, (PVOID)((ULONG_PTR)pFileData + (ULONG_PTR)pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, 0))) {
				DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to write sections\r\n");
				return 0;
			}

		}


	}

	//将ManulMapData给写入到内存

	PVOID pManulMapData=0;
	size_t ManuaMapDataSize = sizeof(Manual_Mapping_data);


	if (!NT_SUCCESS(ReadWrite::MyAllocMem(ProcessId,&pManulMapData,0,&ManuaMapDataSize,MEM_COMMIT,PAGE_READWRITE,0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to alloc manual map data\r\n");

		return 0;
	}

	//修改原型PTE规避检查

	PageAttrHide::ChangeVadAttributes((ULONG_PTR)pManulMapData, MM_READONLY, ProcessId);

	if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pManulMapData, ManualMapData, ManuaMapDataSize, 0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to write manul map data\r\n");

		return 0;
		
	}

	ExFreePool(ManualMapData);

	//ShellCode给映射过去 ShellCode用于自定位

	PVOID pShellCode = 0;
	size_t ShellCodeSize = 0x1000;
	
	if (!NT_SUCCESS(ReadWrite::MyAllocMem(ProcessId, &pShellCode, 0, &ShellCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0))) {

		DbgPrintEx(77,0,"[OxygenDriver]err:Failed  to alloc mem for Shellcode\r\n");

		return 0;

	}

	//修改原型PTE 规避检查

	PageAttrHide::ChangeVadAttributes((ULONG_PTR)pShellCode, MM_READONLY, ProcessId);


	if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pShellCode, ShellCode, ShellCodeSize, 0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to write mem for shellcode\r\n");

		return 0;
	}



	//创建新线程

	HANDLE ThreadId;

	//指定了过ace的话 需要
	////过TP需要去除 去R3的 LdrInitializeThunk的Hook

	if (bPassAce) {

		char OriBytes[14];

		if (!BanACELdrInitializeThunkHook(ProcessId, OriBytes)) {

			DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to ban ace's r3 hook at ldrinitializethunk\r\n");

			return 0;

		}

	}


	if (!NT_SUCCESS(ReadWrite::MyCreateThread(ProcessId, (UINT64)pShellCode, (UINT64)pManulMapData, 0, 0, &ThreadId))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to setup new thread\r\n");

		return 0;


	}


	

	DbgPrintEx(77, 0, "[OxygenDriver]info:Create Thread Successly ThreadId:0x%x\r\n", ThreadId);

	return 1;
}


//注入程序的ShellCode
//用于重定位
void __stdcall ShellCode(Manual_Mapping_data* pData) {


	char* pBase = pData->pBase;

	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	//auto _LoadLibraryA = pData->pLoadLibraryA;
	//auto _GetProcAddress = pData->pGetProcAddress;
	//auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
	//auto _DllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint);



	//重定位表


	char* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				//重定位表有很多个
				//重定位的个数不包括IMAGE_BASE_RELOCATION这个地方
				//重定位的偏移的大小是WORD
				UINT64 AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(short);
				//指向重定位的偏移
				//typedef struct _IMAGE_BASE_RELOCATION {
				//	DWORD   VirtualAddress; //重定位表起始地址的RVA
				//	DWORD   SizeOfBlock;
				//	//  WORD    TypeOffset[1];
				//Windows重定位表是按页涉及的
				//相近的地址,都放在了这一个RVA里面.
				//TypeOffset中高4位是这个重定表项的类型
				//低12位 表示在这个一页(4KB)的偏移
				unsigned short* pRelativeInfo = reinterpret_cast<unsigned short*>(pRelocData + 1);

				for (UINT64 i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					//遍历重定表的TypeOffset
					if (RELOC_FLAG(*pRelativeInfo)) {
						//判断高4位 是否需要重定位

						//只有直接寻址才需要重定位
						//pBase+RVA==需要重定位页面
						//页面+0xfff & TypeOffset 就是要重定位的地址(一个直接地址)
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						//所以我们要把这个地址加上真正装载地址减去ImageBase
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				//下一个重定位表(毕竟不止一个页面需要重定位)
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<char*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	//修复IAT表

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		
		IMAGE_IMPORT_DESCRIPTOR * pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		

		while (pImportDescr->Name) {
			//Name是RVA 指向Dll名称

			HMODULE hDll = pData->pLoadLibraryA(pBase + pImportDescr->Name);

			//INT
			ULONG_PTR* pInt = (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
			//IAT
			ULONG_PTR* pIat = (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);

			if (!pInt) pInt = pIat;

			for (; *pIat; ++pIat, ++pInt) {

				
				if (IMAGE_SNAP_BY_ORDINAL(*pInt)) {
					//如果是序号填充
					*pIat = (ULONG_PTR)pData->pGetProcAddress(hDll,(char*)(*pInt & 0xffff));

				}
				else {
					//按照名称填充
					IMAGE_IMPORT_BY_NAME* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + *pInt);

					*pIat = (ULONG_PTR)pData->pGetProcAddress(hDll, pImport->Name);

				}


			}

			pImportDescr++;


		}


	}


	//填充TLS回调
#define DLL_PROCESS_ATTACH 1

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {


		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		
		//注意 这里要进行重定位
		//TLS表的CallBack要加LocationDelta
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}


	//修复x64下异常表
	auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (excep.Size) {
		pData->pRtlAddFunctionTable((PRUNTIME_FUNCTION)(pBase + excep.VirtualAddress),excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase);
	
	}

	//执行DllMain函数

	((f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint))(pBase, 1, 0);


}


ULONG_PTR  BanACELdrInitializeThunkHook(HANDLE ProcessId,char* OriBytes) {



	ULONG_PTR uLdrInitializeThunk = Global::GetInstance()->fLdrInitializeThunk;
	ULONG_PTR uZwContinue = (ULONG_PTR)Global::GetInstance()->fZwContinue;
	ULONG_PTR uRtlRaiseStatus = (ULONG_PTR)Global::GetInstance()->fRtlRaiseStatus;
	

	CHAR OldBytes[5];


	if (!NT_SUCCESS(ReadWrite::MyReadMem(ProcessId, (PVOID)uLdrInitializeThunk, OldBytes, sizeof(OldBytes), 0))) {

		DbgPrintEx(77,0,"[OxygenDriver]err:Failed to read ldrinitializethunk\r\n");
		return 0;
	}





	DWORD32 dwOldProtect;
	size_t ProtectSize = 0x1000;





	//获取ACE HOOK的真正地址
	ULONG_PTR uCurAddress = uLdrInitializeThunk;

	KdPrint(("LdrInitialzeThunk=0x%p\r\n", uCurAddress));


	while (1) {
		BOOLEAN bDone = 0;
		//ACE不知道有多少层指针 所以需要循环测试
		char bDef;//来确定是不是Hook
		ReadWrite::MyReadMem(ProcessId,(PVOID)(uCurAddress), &bDef, sizeof(bDef), 0);
		switch (bDef)
		{
		case 0xff: {//FF 25调用
			ULONG_PTR uTemp;
			ReadWrite::MyReadMem(ProcessId, (PVOID)(uCurAddress + 6), &uTemp, sizeof(uTemp), 0);
			uCurAddress = uTemp;
			KdPrint(("现在uCurrent=0x%p\r\n", uCurAddress));
			break;
		}
		case 0xe9: {//E9 四字节偏移调用
			int offset;
			ReadWrite::MyReadMem(ProcessId, (PVOID)(uCurAddress + 1), &offset, sizeof(int), 0);
			uCurAddress += 5 + offset;
			KdPrint(("现在uCurrent=0x%p\r\n", uCurAddress));
			break;
		}
		default:
			//如果都不是 说明已经找到地址了 返回即可
			bDone = 1;
			break;
		}
		if (bDone == 1) break;
	}


	ULONG_PTR uSavedCurAddress = uCurAddress;



	DbgPrintEx(77, 0, "[ACE Hook的地方]:0x%p\r\n", uCurAddress);

	//if (uCurAddress == uLdrInitializeThunk) {

	//	//没被Hook
	//	return 1;

	//}

#pragma warning(disable : 4838)
#pragma warning(disable : 4309)
		//修改 Hook的地址 然后ShellCode
	// 
	// 
	//00007FF8FC244C60 <ntdll.LdrInitializeThunk> | 40:53 | push rbx |
	//00007FF8FC244C62 | 48 : 83EC 20 | sub rsp, 0x20 |
	//00007FF8FC244C66 | 48 : 8BD9 | mov rbx, rcx |
	//00007FF8FC244C69 | E8 1A000000 | call ntdll.7FF8FC244C88 |
	//00007FF8FC244C6E | B2 01 | mov dl, 0x1 |
	//00007FF8FC244C70 | 48 : 8BCB | mov rcx, rbx |
	//00007FF8FC244C73 | E8 588D0200 | call <ntdll.ZwContinue> |
	//00007FF8FC244C78 | 8BC8 | mov ecx, eax |
	//00007FF8FC244C7A | E8 81DC0800 | call <ntdll.RtlRaiseStatus> |
	CHAR LdrInitializeThunkShellCode[] = { 0x40,0x53,//push rbx
	0x48,0x83,0xec,0x20,//sub rsp, 0x20
	0x48,0x8b,0xd9,//mov rbx, rcx
	0x48,0x83,0xec,0x08,//sub rsp,8 index=13
	0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xC7,0x04,0x24,0x00,0x00,0x00,0x00, //push rip(自己计算) index=28
	0xff,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//jmp到LdrInit的第一个call index=42
	0xb2,0x01,//mov dl,0x1 index=44
	0x48,0x8b,0xcb,//mov rcx,rbx index = 47
	0x48,0x83,0xec,0x08,//sub rsp,8 index =51
	0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xC7,0x04,0x24,0x00,0x00,0x00,0x00, //push rip(自己计算) index=66
	0xff,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//jmp到ZwContinue 自己填充 index=80
	0x8b,0xc8,//mov ecx,eax index=82
	0x48,0x83,0xec,0x08,//sub rsp,8 index=86
	0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xC7,0x04,0x24,0x00,0x00,0x00,0x00, //push rip(自己计算) index=101
	0xff,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//jmp到RtlRaiseStatus 自己填充 index=155
	};

	//获取那三个Call
	ULONG_PTR uSecondCall = uZwContinue;
	ULONG_PTR uThirdCall = uRtlRaiseStatus;





	KdPrint(("[OxygenDriver]info:进程传过来的Call:0x%p\r\n", Global::GetInstance()->uLdrFirstCall));

	//填充三个Call
	*(ULONG_PTR*)(&LdrInitializeThunkShellCode[34]) = Global::GetInstance()->uLdrFirstCall;
	*(ULONG_PTR*)(&LdrInitializeThunkShellCode[72]) = uSecondCall;
	*(ULONG_PTR*)(&LdrInitializeThunkShellCode[107]) = uThirdCall;

	PVOID pAllocAddr=0;
	size_t AllocSize=0x1000;
	

	if (!NT_SUCCESS(ReadWrite::MyAllocMem(ProcessId, &pAllocAddr, 0, &AllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0))) {
		
		DbgPrintEx(77, 0, "[OxygenDriver]info:Alloc mem for Ldrinitializethunk err!\r\n");

		return 0;
	}


	//修改原型PTE修改属性 规避BE检查

	//PageAttrHide::ChangeVadAttributes((ULONG_PTR)pAllocAddr, MM_READONLY, ProcessId);

	//填充RIP返回地址

	ULONG_PTR uFirstRet = (ULONG_PTR)pAllocAddr + 42;
	ULONG_PTR uSecondRet = (ULONG_PTR)pAllocAddr + 80;
	ULONG_PTR uThiredRet = (ULONG_PTR)pAllocAddr + 115;


#define HIDWORD(l)           ((DWORD32)((((ULONG_PTR)(l)) >> 32) & 0xffffffff)) 
#define LOWDWORD(l)           ((DWORD32)((((ULONG_PTR)(l))) & 0xffffffff)) 

	* (PDWORD32)(&LdrInitializeThunkShellCode[17]) = HIDWORD(uFirstRet);
	*(PDWORD32)(&LdrInitializeThunkShellCode[24]) = LOWDWORD(uFirstRet);

	*(PDWORD32)(&LdrInitializeThunkShellCode[55]) = HIDWORD(uSecondRet);
	*(PDWORD32)(&LdrInitializeThunkShellCode[62]) = LOWDWORD(uSecondRet);

	*(PDWORD32)(&LdrInitializeThunkShellCode[90]) = HIDWORD(uThiredRet);
	*(PDWORD32)(&LdrInitializeThunkShellCode[97]) = LOWDWORD(uThiredRet);



	if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pAllocAddr, LdrInitializeThunkShellCode, sizeof(LdrInitializeThunkShellCode), 0))) {

		DbgPrintEx(77,0,"[OxygenDriver]info:Failed to write mem for Ldrinitializethunk\r\n");
		
		return 0;

	}



	//修改ACE Hook的地方
	

	KdPrint(("[OxygenDriver]:SavedCurAddress==0x%p\r\n", uSavedCurAddress));

	ReadWrite::MyProtectMem(ProcessId, (PVOID*)&uCurAddress, &ProtectSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//注意 这个时候uCurAddress已经改变了
	//所以保存一下 因为ProtectMem会修改

	//CHAR aHookOriBytes[14];

#define HOOKSIZE 14


	if (!NT_SUCCESS(ReadWrite::MyReadMem(ProcessId, (PVOID)uSavedCurAddress, OriBytes, HOOKSIZE, 0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to write mem for hook addr\r\n");

		return 0;
	}

	CHAR JmpShellCode[] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00 };


	*(ULONG_PTR*)(&JmpShellCode[6]) = (ULONG_PTR)pAllocAddr;



	if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, (PVOID)uSavedCurAddress, JmpShellCode, sizeof(JmpShellCode), 0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to write mem for hook addr\r\n");

		return 0;

	}

	return 1;

}

