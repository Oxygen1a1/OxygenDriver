#include "Injector.h"
#include "Global.h"
#include "ReadWrite.h"



using namespace Injector_x64;

//方便释放
#define MEM_DLL_TAGS 0x5556

//Dll映射的内存
PVOID g_pMemDll;

BOOLEAN MmMapDll(HANDLE ProcessId, PVOID pFileData, UINT64 FileSize);

BOOLEAN Injector_x64::MmInjector_x64(HANDLE ProcessId,const wchar_t* wszDllPath) {
	
	UNREFERENCED_PARAMETER(wszDllPath);
	UNREFERENCED_PARAMETER(ProcessId);


	HANDLE	hFile = 0;
	OBJECT_ATTRIBUTES	objattr;
	NTSTATUS	status=STATUS_SUCCESS;
	//因为穿的参数都是0环地址 所以要改一下PreviousMode

#pragma warning(disable : 4267)

	UNICODE_STRING		usR0DllPath = RTL_CONSTANT_STRING(L"\\??\\C:\\Users\\admin\\Desktop\\Target.dll");
	IO_STATUS_BLOCK		IoStatusBlock = { 0 };
	LARGE_INTEGER		lainter = { 0 };
	FILE_STANDARD_INFORMATION	fileinfo = {0};
	UINT64 FileSize=0;
	//初始化Attributes
	InitializeObjectAttributes(&objattr,&usR0DllPath,0x40,0,0);

	ReadWrite::ChangePreviousMode();//修改PreviosuMode


	//调试用
	DbgBreakPoint();


	status = NtCreateFile(&hFile, GENERIC_WRITE | GENERIC_READ, &objattr, &IoStatusBlock, &lainter, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, 0, 0);
	
	
	//NtReadFile()

	if (!NT_SUCCESS(status)) {

		//err

		DbgPrintEx(77, 0, "[OxygenDriver]:err:Failed to create file\r\n");


		ReadWrite::ResumePreviousMode();

		return false;
	}



	status=NtQueryInformationFile(hFile, &IoStatusBlock, &fileinfo,sizeof(fileinfo), FileStandardInformation);

	FileSize = fileinfo.AllocationSize.QuadPart;

	if (!NT_SUCCESS(status)) {

		//err

		DbgPrintEx(77, 0, "[OxygenDriver]:err:Failed to query file\r\n");


		ReadWrite::ResumePreviousMode();

		return false;
	}
	
#pragma warning(disable : 4244)
	g_pMemDll=ExAllocatePoolWithTag(PagedPool, FileSize, MEM_DLL_TAGS);


	memset(g_pMemDll, 0, fileinfo.AllocationSize.QuadPart);

	LARGE_INTEGER byteoffset = { 0 };


	status = NtReadFile(hFile, 0, 0, 0, &IoStatusBlock, g_pMemDll, FileSize,&byteoffset, 0);

	//刷新一下 不然要等待
	ZwFlushBuffersFile(hFile, &IoStatusBlock);

	if (!NT_SUCCESS(status)) {

		//err

		DbgPrintEx(77, 0, "[OxygenDriver]:err:Failed to read file\r\n");


		ExFreePool(g_pMemDll);

		ReadWrite::ResumePreviousMode();
		return false;

	}



	ReadWrite::ResumePreviousMode();




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

	status=ReadWrite::MyAllocMem(ProcessId,(PVOID*)&pStartMapAddr,0,&size,MEM_COMMIT, PAGE_READWRITE);

	if (!NT_SUCCESS(status)) {

		//分配失败

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to alloc mem\r\n");

		return 0;
	}





}