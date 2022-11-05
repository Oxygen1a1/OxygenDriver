#pragma once
#include "Global.h"
#include <ntimage.h>

#define X64 0x8664
#define X86 0x14c




namespace Injector_x64 {

//确定是否需要重定位
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG RELOC_FLAG64



	typedef PVOID HINSTANCE, HMODULE;
	typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
		DWORD32 BeginAddress;
		DWORD32 EndAddress;
		union {
			DWORD32 UnwindInfoAddress;
			DWORD32 UnwindData;
		} DUMMYUNIONNAME;
	} *PRUNTIME_FUNCTION;
	using f_LoadLibraryA = HINSTANCE(__stdcall*)(const char* lpLibFilename);
	using f_GetProcAddress = PVOID(__stdcall*)(HMODULE hModule, LPCSTR lpProcName);
	using f_DLL_ENTRY_POINT = BOOLEAN(__stdcall*)(void* hDll, DWORD32 dwReason, void* pReserved);
	using f_RtlAddFunctionTable = BOOLEAN(__stdcall*)(PRUNTIME_FUNCTION FunctionTable, DWORD32 EntryCount, DWORD64 BaseAddress);

	struct Manual_Mapping_data//内存映射dll对象
	{
		//用于重定位IAT
		f_LoadLibraryA pLoadLibraryA;
		f_GetProcAddress pGetProcAddress;

		//x64专有
		f_RtlAddFunctionTable pRtlAddFunctionTable;

		char* pBase;
		HINSTANCE hMod;
		DWORD32 dwReadson;
		PVOID reservedParam;

	};



	BOOLEAN MmInjector_x64_BypassProtect(HANDLE ProcessId, const wchar_t* wszDllPath,BOOLEAN bPassAce);

	/*BOOLEAN MemInject_PassTp_x64(HANDLE ProcessId,const wchar_t* wszDllPath);


	BOOLEAN MmInject_PassTp_x86(HANDLE ProcessId, const wchar_t* wszDllPath);


	BOOLEAN MmInject_PsssBe_x64(HANDLE ProcessId, const wchar_t* wszDllPath);*/

}

namespace Injector_x86 {



}