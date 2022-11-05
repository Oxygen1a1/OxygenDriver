#include "Injector.h"
#include "Global.h"
#include "ReadWrite.h"
#include "PageAttrHide.h"


using namespace Injector_x64;

//�����ͷ�
#define MEM_DLL_TAGS 0x5556

//Dllӳ����ڴ�
PVOID g_pMemDll;

//ȥ��ACE����R3 ��Hook
ULONG_PTR  BanACELdrInitializeThunkHook(HANDLE ProcessId, char* OriBytes);


//����Dll�ض�λ��ShellCode
void __stdcall ShellCode(Manual_Mapping_data* pData);
BOOLEAN MmMapDll(HANDLE ProcessId, PVOID pFileData, UINT64 FileSize,BOOLEAN bPassAce);

BOOLEAN Injector_x64::MmInjector_x64_BypassProtect(HANDLE ProcessId,const wchar_t* wszDllPath,BOOLEAN bPassAce) {
	
	UNREFERENCED_PARAMETER(wszDllPath);
	UNREFERENCED_PARAMETER(ProcessId);


	HANDLE	hFile = 0;
	OBJECT_ATTRIBUTES	objattr;
	NTSTATUS	status=STATUS_SUCCESS;
	//��Ϊ���Ĳ�������0����ַ ����Ҫ��һ��PreviousMode

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
	//��ʼ��Attributes
	InitializeObjectAttributes(&objattr,&usR0DllPath,0x40,0,0);

	

	ReadWrite::ChangePreviousMode();//�޸�PreviosuMode


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

	//ˢ��һ�� ��ȻҪ�ȴ�
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

	//��ʼMap�ĵ�ַ
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
		//����x64�ļ�

		DbgPrintEx(77, 0, "[OxygenDriver]err:File archtrue not match\r\n");

		return 0;

	}


	size_t size = (size_t)pOptHeader->SizeOfImage;

	status=ReadWrite::MyAllocMem(ProcessId,(PVOID*)&pStartMapAddr,0,&size,MEM_COMMIT, PAGE_EXECUTE_READWRITE,0);

	//�޸�ԭ��PTE ��ܼ��

	PageAttrHide::ChangeVadAttributes((ULONG_PTR)pStartMapAddr, MM_READONLY,ProcessId);

	if (!NT_SUCCESS(status)) {

		//����ʧ��

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to alloc mem\r\n");

		return 0;
	}

	//����Mem_Map_Dll�ṹ��

	Manual_Mapping_data* ManualMapData=(Manual_Mapping_data*)ExAllocatePoolWithTag(NonPagedPool,sizeof(ManualMapData)+2,'MMD');

	ManualMapData->dwReadson = 0;
	ManualMapData->pGetProcAddress = (f_GetProcAddress)Global::GetInstance()->pGetProcAddress;
	ManualMapData->pLoadLibraryA = (f_LoadLibraryA)Global::GetInstance()->pLoadLibraryA;
	ManualMapData->pBase = pStartMapAddr;
	ManualMapData->reservedParam = 0;
	ManualMapData->pRtlAddFunctionTable = (f_RtlAddFunctionTable)Global::GetInstance()->pRtlAddFunctionTable;



	//��ʼд��PE�ļ��ṹ

	//д��PEͷ

	if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pStartMapAddr, pFileData, 0x1000, 0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to Write PE head\r\n");

		return 0;
	}

	//д��PE�ṹ�ĸ�����

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	//��ΪSection�������� ���Կ���ֱ��++
	//VirtualAddress=RVA PointerToRawData==FOA
	for (int i = 0; i < pFileHeader->NumberOfSections; i++,pSectionHeader++) {
		
		if (pSectionHeader->SizeOfRawData) {
			if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pStartMapAddr + pSectionHeader->VirtualAddress, (PVOID)((ULONG_PTR)pFileData + (ULONG_PTR)pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, 0))) {
				DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to write sections\r\n");
				return 0;
			}

		}


	}

	//��ManulMapData��д�뵽�ڴ�

	PVOID pManulMapData=0;
	size_t ManuaMapDataSize = sizeof(Manual_Mapping_data);


	if (!NT_SUCCESS(ReadWrite::MyAllocMem(ProcessId,&pManulMapData,0,&ManuaMapDataSize,MEM_COMMIT,PAGE_READWRITE,0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to alloc manual map data\r\n");

		return 0;
	}

	//�޸�ԭ��PTE��ܼ��

	PageAttrHide::ChangeVadAttributes((ULONG_PTR)pManulMapData, MM_READONLY, ProcessId);

	if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pManulMapData, ManualMapData, ManuaMapDataSize, 0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to write manul map data\r\n");

		return 0;
		
	}

	ExFreePool(ManualMapData);

	//ShellCode��ӳ���ȥ ShellCode�����Զ�λ

	PVOID pShellCode = 0;
	size_t ShellCodeSize = 0x1000;
	
	if (!NT_SUCCESS(ReadWrite::MyAllocMem(ProcessId, &pShellCode, 0, &ShellCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0))) {

		DbgPrintEx(77,0,"[OxygenDriver]err:Failed  to alloc mem for Shellcode\r\n");

		return 0;

	}

	//�޸�ԭ��PTE ��ܼ��

	PageAttrHide::ChangeVadAttributes((ULONG_PTR)pShellCode, MM_READONLY, ProcessId);


	if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pShellCode, ShellCode, ShellCodeSize, 0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to write mem for shellcode\r\n");

		return 0;
	}



	//�������߳�

	HANDLE ThreadId;

	//ָ���˹�ace�Ļ� ��Ҫ
	////��TP��Ҫȥ�� ȥR3�� LdrInitializeThunk��Hook

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


//ע������ShellCode
//�����ض�λ
void __stdcall ShellCode(Manual_Mapping_data* pData) {


	char* pBase = pData->pBase;

	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	//auto _LoadLibraryA = pData->pLoadLibraryA;
	//auto _GetProcAddress = pData->pGetProcAddress;
	//auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
	//auto _DllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint);



	//�ض�λ��


	char* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				//�ض�λ���кܶ��
				//�ض�λ�ĸ���������IMAGE_BASE_RELOCATION����ط�
				//�ض�λ��ƫ�ƵĴ�С��WORD
				UINT64 AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(short);
				//ָ���ض�λ��ƫ��
				//typedef struct _IMAGE_BASE_RELOCATION {
				//	DWORD   VirtualAddress; //�ض�λ����ʼ��ַ��RVA
				//	DWORD   SizeOfBlock;
				//	//  WORD    TypeOffset[1];
				//Windows�ض�λ���ǰ�ҳ�漰��
				//����ĵ�ַ,����������һ��RVA����.
				//TypeOffset�и�4λ������ض����������
				//��12λ ��ʾ�����һҳ(4KB)��ƫ��
				unsigned short* pRelativeInfo = reinterpret_cast<unsigned short*>(pRelocData + 1);

				for (UINT64 i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					//�����ض����TypeOffset
					if (RELOC_FLAG(*pRelativeInfo)) {
						//�жϸ�4λ �Ƿ���Ҫ�ض�λ

						//ֻ��ֱ��Ѱַ����Ҫ�ض�λ
						//pBase+RVA==��Ҫ�ض�λҳ��
						//ҳ��+0xfff & TypeOffset ����Ҫ�ض�λ�ĵ�ַ(һ��ֱ�ӵ�ַ)
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						//��������Ҫ�������ַ��������װ�ص�ַ��ȥImageBase
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				//��һ���ض�λ��(�Ͼ���ֹһ��ҳ����Ҫ�ض�λ)
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<char*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	//�޸�IAT��

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		
		IMAGE_IMPORT_DESCRIPTOR * pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		

		while (pImportDescr->Name) {
			//Name��RVA ָ��Dll����

			HMODULE hDll = pData->pLoadLibraryA(pBase + pImportDescr->Name);

			//INT
			ULONG_PTR* pInt = (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
			//IAT
			ULONG_PTR* pIat = (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);

			if (!pInt) pInt = pIat;

			for (; *pIat; ++pIat, ++pInt) {

				
				if (IMAGE_SNAP_BY_ORDINAL(*pInt)) {
					//�����������
					*pIat = (ULONG_PTR)pData->pGetProcAddress(hDll,(char*)(*pInt & 0xffff));

				}
				else {
					//�����������
					IMAGE_IMPORT_BY_NAME* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + *pInt);

					*pIat = (ULONG_PTR)pData->pGetProcAddress(hDll, pImport->Name);

				}


			}

			pImportDescr++;


		}


	}


	//���TLS�ص�
#define DLL_PROCESS_ATTACH 1

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {


		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		
		//ע�� ����Ҫ�����ض�λ
		//TLS���CallBackҪ��LocationDelta
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}


	//�޸�x64���쳣��
	auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (excep.Size) {
		pData->pRtlAddFunctionTable((PRUNTIME_FUNCTION)(pBase + excep.VirtualAddress),excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase);
	
	}

	//ִ��DllMain����

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





	//��ȡACE HOOK��������ַ
	ULONG_PTR uCurAddress = uLdrInitializeThunk;

	KdPrint(("LdrInitialzeThunk=0x%p\r\n", uCurAddress));


	while (1) {
		BOOLEAN bDone = 0;
		//ACE��֪���ж��ٲ�ָ�� ������Ҫѭ������
		char bDef;//��ȷ���ǲ���Hook
		ReadWrite::MyReadMem(ProcessId,(PVOID)(uCurAddress), &bDef, sizeof(bDef), 0);
		switch (bDef)
		{
		case 0xff: {//FF 25����
			ULONG_PTR uTemp;
			ReadWrite::MyReadMem(ProcessId, (PVOID)(uCurAddress + 6), &uTemp, sizeof(uTemp), 0);
			uCurAddress = uTemp;
			KdPrint(("����uCurrent=0x%p\r\n", uCurAddress));
			break;
		}
		case 0xe9: {//E9 ���ֽ�ƫ�Ƶ���
			int offset;
			ReadWrite::MyReadMem(ProcessId, (PVOID)(uCurAddress + 1), &offset, sizeof(int), 0);
			uCurAddress += 5 + offset;
			KdPrint(("����uCurrent=0x%p\r\n", uCurAddress));
			break;
		}
		default:
			//��������� ˵���Ѿ��ҵ���ַ�� ���ؼ���
			bDone = 1;
			break;
		}
		if (bDone == 1) break;
	}


	ULONG_PTR uSavedCurAddress = uCurAddress;



	DbgPrintEx(77, 0, "[ACE Hook�ĵط�]:0x%p\r\n", uCurAddress);

	//if (uCurAddress == uLdrInitializeThunk) {

	//	//û��Hook
	//	return 1;

	//}

#pragma warning(disable : 4838)
#pragma warning(disable : 4309)
		//�޸� Hook�ĵ�ַ Ȼ��ShellCode
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
	0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xC7,0x04,0x24,0x00,0x00,0x00,0x00, //push rip(�Լ�����) index=28
	0xff,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//jmp��LdrInit�ĵ�һ��call index=42
	0xb2,0x01,//mov dl,0x1 index=44
	0x48,0x8b,0xcb,//mov rcx,rbx index = 47
	0x48,0x83,0xec,0x08,//sub rsp,8 index =51
	0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xC7,0x04,0x24,0x00,0x00,0x00,0x00, //push rip(�Լ�����) index=66
	0xff,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//jmp��ZwContinue �Լ���� index=80
	0x8b,0xc8,//mov ecx,eax index=82
	0x48,0x83,0xec,0x08,//sub rsp,8 index=86
	0xC7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xC7,0x04,0x24,0x00,0x00,0x00,0x00, //push rip(�Լ�����) index=101
	0xff,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//jmp��RtlRaiseStatus �Լ���� index=155
	};

	//��ȡ������Call
	ULONG_PTR uSecondCall = uZwContinue;
	ULONG_PTR uThirdCall = uRtlRaiseStatus;





	KdPrint(("[OxygenDriver]info:���̴�������Call:0x%p\r\n", Global::GetInstance()->uLdrFirstCall));

	//�������Call
	*(ULONG_PTR*)(&LdrInitializeThunkShellCode[34]) = Global::GetInstance()->uLdrFirstCall;
	*(ULONG_PTR*)(&LdrInitializeThunkShellCode[72]) = uSecondCall;
	*(ULONG_PTR*)(&LdrInitializeThunkShellCode[107]) = uThirdCall;

	PVOID pAllocAddr=0;
	size_t AllocSize=0x1000;
	

	if (!NT_SUCCESS(ReadWrite::MyAllocMem(ProcessId, &pAllocAddr, 0, &AllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0))) {
		
		DbgPrintEx(77, 0, "[OxygenDriver]info:Alloc mem for Ldrinitializethunk err!\r\n");

		return 0;
	}


	//�޸�ԭ��PTE�޸����� ���BE���

	//PageAttrHide::ChangeVadAttributes((ULONG_PTR)pAllocAddr, MM_READONLY, ProcessId);

	//���RIP���ص�ַ

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



	//�޸�ACE Hook�ĵط�
	

	KdPrint(("[OxygenDriver]:SavedCurAddress==0x%p\r\n", uSavedCurAddress));

	ReadWrite::MyProtectMem(ProcessId, (PVOID*)&uCurAddress, &ProtectSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//ע�� ���ʱ��uCurAddress�Ѿ��ı���
	//���Ա���һ�� ��ΪProtectMem���޸�

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

