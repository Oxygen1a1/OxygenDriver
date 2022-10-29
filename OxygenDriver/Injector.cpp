#include "Injector.h"
#include "Global.h"
#include "ReadWrite.h"



using namespace Injector_x64;

//�����ͷ�
#define MEM_DLL_TAGS 0x5556

//Dllӳ����ڴ�
PVOID g_pMemDll;

//����Dll�ض�λ��ShellCode
void __stdcall ShellCode(Manual_Mapping_data* pData);


BOOLEAN MmMapDll(HANDLE ProcessId, PVOID pFileData, UINT64 FileSize);

BOOLEAN Injector_x64::MmInjector_x64(HANDLE ProcessId,const wchar_t* wszDllPath) {
	
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


	

	if (!MmMapDll(ProcessId, g_pMemDll, FileSize)) {

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
BOOLEAN MmMapDll(HANDLE ProcessId, PVOID pFileData, UINT64 FileSize) {
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


	if (!NT_SUCCESS(ReadWrite::MyWriteMem(ProcessId, pShellCode, ShellCode, ShellCodeSize, 0))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to write mem for shellcode\r\n");

		return 0;
	}



	//�������߳�

	HANDLE ThreadId;

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
		//�в�� ��Ҫ�ض�λ
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			//��ѡͷ����Ŀ¼����ض�λ��
			
			//�ҵ��ض�λ�������ָ�� �ض�λ��һ����ֻ��һ�� ����size��ȡ����λ��
			IMAGE_BASE_RELOCATION* pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			//size��ָ�ض�λ������Ĵ�С
			//�ض�λ���Ǹ��䳤�ģ�
			IMAGE_BASE_RELOCATION* pRelocEnd = (IMAGE_BASE_RELOCATION*)((ULONG_PTR)pRelocData + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

			
			while (pRelocData<pRelocEnd && pRelocData->SizeOfBlock) {

				//ÿһ���ض�λ���Ǹ��䳤���� 
				//typedef struct _IMAGE_BASE_RELOCATION {
				//	ULONG   VirtualAddress;
				//	ULONG   SizeOfBlock;
				//	//  USHORT  TypeOffset[1];
				//} IMAGE_BASE_RELOCATION;
				//TypeOffset�����ض�λ���� ������ǰ��8���ֽ�
				UINT32 AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

				//��ȡ��һ��TypeOffset
				INT16* pRelativeInfo= (INT16*)(pRelocData + 1);

				for (UINT32 i = 0; i < AmountOfEntries; i++, pRelativeInfo++) {

					if (RELOC_FLAG64(*pRelativeInfo)) {
						//����������жϵ�ǰ���TypeOffset�Ƿ���Ҫ�ض�λ

						//pBase+RVA==��Ҫ�ض�λҳ��
						//ҳ��+0xfff & TypeOffset ����Ҫ�ض�λ�ĵ�ַ(һ��ֱ�ӵ�ַ)
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						//��������Ҫ�������ַ��������װ�ص�ַ��ȥImageBase
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);


					}


				}

				//��һ���ض�λ��
				pRelocData = (IMAGE_BASE_RELOCATION*)((ULONG_PTR)pRelocData + pRelocData->SizeOfBlock);
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