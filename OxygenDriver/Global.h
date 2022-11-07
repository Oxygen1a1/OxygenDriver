#pragma once
#include <ntifs.h>
#include <ntddk.h>

#define CTL_CODE_INIT CTL_CODE(0x8000,0x801,0,0)





//用于进线程创建的AttributeList 0环要转成CreateProcessContext 变长数组
typedef struct _SECURITY_ATTRIBUTES {
	DWORD32 nLength;
	PVOID lpSecurityDescriptor;
	BOOLEAN bInheritHandle;
} SECURITY_ATTRIBUTES, * PSECURITY_ATTRIBUTES, * LPSECURITY_ATTRIBUTES;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY {
	UINT64 Attribute;
	SIZE_T size;
	UINT64 Vaule;
	UINT64 Unknown;
}NT_PROC_THREAD_ATTRIBUTE_ENTRY,* PNT_PROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST {
	UINT64 Length;
	_NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
}NT_PROC_THREAD_ATTRIBUTE_LIST,*PNT_PROC_THREAD_ATTRIBUTE_LIST;

typedef struct _LDR_DATA
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;
	/*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;
	/*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;
	/*0x030*/     VOID* DllBase;
	/*0x038*/     VOID* EntryPoint;
	/*0x040*/     ULONG32      SizeOfImage;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _UNICODE_STRING FullDllName;
	/*0x058*/     struct _UNICODE_STRING BaseDllName;
	/*0x068*/     ULONG32      Flags;
	/*0x06C*/     UINT16       LoadCount;
	/*0x06E*/     UINT16       TlsIndex;
	union
	{
		/*0x070*/         struct _LIST_ENTRY HashLinks;
		struct a
		{
			/*0x070*/             VOID* SectionPointer;
			/*0x078*/             ULONG32      CheckSum;
			/*0x07C*/             UINT8        _PADDING1_[0x4];
		};
	};
	union
	{
		/*0x080*/         ULONG32      TimeDateStamp;
		/*0x080*/         VOID* LoadedImports;
	};
	/*0x088*/     struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	/*0x090*/     VOID* PatchInformation;
	/*0x098*/     struct _LIST_ENTRY ForwarderLinks;
	/*0x0A8*/     struct _LIST_ENTRY ServiceTagLinks;
	/*0x0B8*/     struct _LIST_ENTRY StaticLinks;
	/*0x0C8*/     VOID* ContextInformation;
	/*0x0D0*/     UINT64       OriginalBase;
	/*0x0D8*/     union _LARGE_INTEGER LoadTime;
}LDR_DATA, * PLDR_DATA;

//这里字节对齐要采用默认，不要按1对齐，这样才符合32位和64位结构体
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union b
	{
		LIST_ENTRY HashLinks;
		struct e
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union e
	{
		struct c
		{
			ULONG TimeDateStamp;
		};
		struct d
		{
			PVOID LoadedImports;
		};
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

struct InitPdb
{
	ULONG_PTR uRvaNtWrite;
	ULONG_PTR uRvaNtAlloc;
	ULONG_PTR uRvaNtCreateThread;
	ULONG_PTR uRvaNtRead;
	ULONG_PTR uRvaNtProtect;
	ULONG_PTR uThreadPreviouMode;
	ULONG_PTR uVadRoot;
	ULONG_PTR uPspNotifyEnableMaskRva;
	ULONG_PTR uApcState;
	ULONG_PTR uUserApcPendingAll;
	ULONG_PTR uRvaMmpfndatabase;
	ULONG_PTR uOriginPte;
	ULONG_PTR fLdrInitializeThunk = 0;
	ULONG_PTR fZwContinue = 0;
	ULONG_PTR fRtlRaiseStatus = 0;
	//Shellcode 加载DLl
	ULONG_PTR pLoadLibraryA=0;
	ULONG_PTR pGetProcAddress=0;
	//x64专属
	ULONG_PTR pRtlAddFunctionTable=0;

	//因为是在对方Hook里面 所以把LdrInitializeThunk的第一个Call地址传一下
	ULONG_PTR uLdrFirstCall = 0;
	ULONG_PTR pKeServiceDescriptorTable = 0;

};

//内核函数函数指针定义
typedef NTSTATUS(__fastcall* pNtReadVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS(__fastcall* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, size_t BufferLength, PULONG ReturnLength OPTIONAL);
typedef INT64(__fastcall* pNtAllocateVirtualMemory)(INT64 hProcess, PVOID* plpAddress, INT64 Zero, INT64* pSize, INT64 flAllocationType, INT64 flProtect);
typedef NTSTATUS(__fastcall* pNtCreateThreadEx)(HANDLE phNewThreadHandle, DWORD32 Access, LPSECURITY_ATTRIBUTES ThreadAttribute, HANDLE hProcess, UINT64 lpStartAddress, UINT64 lpParameter, DWORD32 CreateFlags, UINT64 ZeroBit, UINT64 StackSize, UINT64 ZeroBit2, _NT_PROC_THREAD_ATTRIBUTE_LIST* pAttributeList);
typedef NTSTATUS(__fastcall* pNtProtectVirtualMemory)(HANDLE hProcess, PVOID* plpAddress, SIZE_T* pSize_t, DWORD32 dwNewProtect, PDWORD32 OldProtect);



class Global {
public:
	//是否已经初始化
	bool bInitPdb=0;



	pNtWriteVirtualMemory pNtWrite=0;
	pNtAllocateVirtualMemory pNtAlloc=0;
	pNtCreateThreadEx pNtCreateThread=0;
	pNtReadVirtualMemory pNtRead=0;
	pNtProtectVirtualMemory pNtProtect=0;

	ULONG_PTR fLdrInitializeThunk=0;
	ULONG_PTR fZwContinue=0;
	ULONG_PTR fRtlRaiseStatus=0;
	ULONG_PTR uThreadPreviouMode=0;
	ULONG_PTR uApcState = 0;
	ULONG_PTR uApcUserPendingAll = 0;
	ULONG_PTR uVadRoot=0;
	PLDR_DATA_TABLE_ENTRY uDriverSection = 0;//遍历Ldr_table_list_entry 找到ntosknrl基质
	ULONG_PTR uNtosnrlBase = 0;
	//Shellcode 加载DLl
	ULONG_PTR pLoadLibraryA=0;
	ULONG_PTR pGetProcAddress=0;

	//x64专属
	ULONG_PTR pRtlAddFunctionTable=0;

	
	ULONG_PTR uPspNotifyEnableMask = 0;
	//物理页帧数据库
	ULONG_PTR uMmpfnDatabase = 0;
	//原型PTE的偏移
	ULONG_PTR uOriginPte=0;

	ULONG_PTR uLdrFirstCall = 0;

	//ssdt
	ULONG_PTR pKeServiceDescriptorTable = 0;
	//c++单例设计模式
	static Global* GetInstance();

private:
	static Global* m_pInstance;
};