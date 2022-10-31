#include "ReadWrite.h"
#include <ntddk.h>
#include <intrin.h>

using namespace ReadWrite;


bool WriteByMdl(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, size_t BufferLength, PULONG ReturnLength OPTIONAL);
void OnWPbit(KIRQL irpl);
KIRQL OffWPbit();
bool BanThreadNotify();
bool ResumeThreadNotify();


void ReadWrite::ChangePreviousMode() {

	ULONG_PTR uOffset = Global::GetInstance()->uThreadPreviouMode;

	PETHREAD pCurThread = PsGetCurrentThread();

	if (!pCurThread) {
		//err
		KdPrint(("[OxygenDriver]err:Failed to get current thread\n"));
		return;
	}
	
	
	*(PUCHAR)((ULONG_PTR)pCurThread + uOffset) = 0;
	
}

void ReadWrite::ResumePreviousMode() {

	ULONG_PTR uOffset = Global::GetInstance()->uThreadPreviouMode;

	PETHREAD pCurThread = PsGetCurrentThread();

	if (!pCurThread) {
		//err
		KdPrint(("[OxygenDriver]err:Failed to get current thread\n"));
		return;
	}

	*(PUCHAR)((ULONG_PTR)pCurThread + uOffset) = 1;


}


NTSTATUS ReadWrite::MyWriteMem(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, size_t BufferLength, PULONG ReturnLength OPTIONAL) {

	HANDLE hProcess;
	CLIENT_ID cid;
	cid.UniqueProcess = ProcessId;
	cid.UniqueThread = 0;
	OBJECT_ATTRIBUTES objattr = { 0 };
	InitializeObjectAttributes(&objattr, 0, 0, 0, 0);

	//权限无所谓
	NTSTATUS status = ZwOpenProcess(&hProcess, 0, &objattr, &cid);

	if (hProcess == 0) {
		//err
		KdPrint(("[OxygenDriver]err:open process err!\n"));
		return STATUS_UNSUCCESSFUL;

	}


	ChangePreviousMode();

	status = Global::GetInstance()->pNtWrite(hProcess, BaseAddress, Buffer, BufferLength, ReturnLength);

	if (!NT_SUCCESS(status)) {
		//err
		KdPrint(("[OxygenDriver]err:common Ntwrite failed,now try to use MdlWrite\n"));

		bool bOk = WriteByMdl(ProcessId, BaseAddress, Buffer, BufferLength, nullptr);

		if (!bOk) {

			KdPrint(("[OxygenDriver]err:failed to write by mdl! processId:%d write at:0x%p\n", ProcessId, BaseAddress));

			ResumePreviousMode();

			return STATUS_UNSUCCESSFUL;

		}

		KdPrint(("[OxygenDriver]Info:mdl write success!\n"));
	}

	ResumePreviousMode();

	return STATUS_SUCCESS;
}

NTSTATUS ReadWrite::MyAllocMem(HANDLE ProcessId,PVOID* pLpAddress,INT64 ZeroBits,SIZE_T* pSize,DWORD32 flAllocationType,DWORD32 flProtect,ULONG_PTR* lpAllocAddr){
	
	HANDLE hProcess;
	CLIENT_ID cid;
	cid.UniqueProcess = ProcessId;
	cid.UniqueThread = 0;
	OBJECT_ATTRIBUTES objattr = { 0 };
	PEPROCESS Process = 0;
	KAPC_STATE ApcState;



	InitializeObjectAttributes(&objattr,0,0,0,0);
	memset(&ApcState, 0, sizeof(ApcState));
	//权限无所谓
	NTSTATUS status=ZwOpenProcess(&hProcess, 0, &objattr, &cid);

	status = PsLookupProcessByProcessId(ProcessId, &Process);
	
	
	if (!NT_SUCCESS(status)) {
		//err
		KdPrint(("[OxygenDriver]err:open process err!\n"));
		return STATUS_UNSUCCESSFUL;

	}



	ChangePreviousMode();

	//挂靠进程

	KeStackAttachProcess(Process, &ApcState);

	//先申请一块可读写的内存 不然没办法memset 一会再改回来

	UNREFERENCED_PARAMETER(flProtect);

	status = ZwAllocateVirtualMemory(NtCurrentProcess(), pLpAddress, ZeroBits, pSize, flAllocationType, flProtect);

	if (!NT_SUCCESS(status)) {

		//err
		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to alloc virtualmemory!,ErrCode=0x%x\n", status);

		KeUnstackDetachProcess(&ApcState);
		ResumePreviousMode();
		return STATUS_UNSUCCESSFUL;

	}



	//附加进程 刷新一下内存 memset 让他挂一下物理页 不然没办法直接读写
	_try{

	memset(*pLpAddress, 0, *pSize);

	}_except(1) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Flush mem err but maybe it doesn't matter\r\n");
		
		ResumePreviousMode();
	}


	KeUnstackDetachProcess(&ApcState);

	ResumePreviousMode();


	if (MmIsAddressValid((PVOID)lpAllocAddr)) {

		*lpAllocAddr = *(ULONG_PTR*)pLpAddress;
	}
	


	DbgPrintEx(77, 0, "[OxygenDriver]info:alloc success,alloc addr:0x%p\n", *pLpAddress);


	



	return STATUS_SUCCESS;
}

NTSTATUS ReadWrite::MyCreateThread(HANDLE ProcessId,UINT64 lpStartAddress,UINT64 lParam,DWORD32 CreateFlags,UINT64 StackSize,OUT PHANDLE hThread) {
	CLIENT_ID cid = {0};
	OBJECT_ATTRIBUTES objattr = { 0 };
	InitializeObjectAttributes(&objattr, 0, 0, 0, 0);
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hProcess = 0;
	cid.UniqueProcess = ProcessId;


	status = ZwOpenProcess(&hProcess, 0, &objattr, &cid);

	if (!NT_SUCCESS(status)) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to get process handle errcode=0x%x\n", status);


		return status;
	}


	//这些参数均是逆的3环到0环传参过程
	//HANDLE phNewThreadHandle, DWORD32 Access, UINT64 ThreadAttribute, HANDLE hProcess, UINT64 lpStartAddress, 
	//UINT64 lpParameter, DWORD32 CreateFlags, UINT64 ZeroBit, UINT64 StackSize, UINT64 ZeroBit2, INT64 pAttributeList

	//初始化AttributeList
	ULONG_PTR pTeb;
	ULONG_PTR pClientID[2];

	_NT_PROC_THREAD_ATTRIBUTE_LIST* AttributeList = (_NT_PROC_THREAD_ATTRIBUTE_LIST*)ExAllocatePoolWithTag(NonPagedPool,0x48,'Thre');

	AttributeList->Length = 0x48;
	AttributeList->Entry[0].Attribute = 0x10003;
	AttributeList->Entry[0].size = 0x10;
	AttributeList->Entry[0].Vaule = (UINT64)pClientID;
	AttributeList->Entry[0].Unknown = 0;
	AttributeList->Entry[1].Attribute = 0x10004;
	AttributeList->Entry[1].size = 0x8;
	AttributeList->Entry[1].Vaule = (UINT64)&pTeb;
	AttributeList->Entry[1].Unknown = 0;



	ChangePreviousMode();

	BanThreadNotify();
	
	status = Global::GetInstance()->pNtCreateThread(hThread, 0, 0, hProcess, lpStartAddress, lParam, CreateFlags, 0, StackSize, 0, AttributeList);

	if (!NT_SUCCESS(status)) {

		//err

		DbgPrintEx(77, 0, "Failed to create thread!errcode=0x%x\n", status);

		ResumeThreadNotify();

		ResumePreviousMode();

		ExFreePool(AttributeList);

		return status;
	}


	ExFreePool(AttributeList);

	ResumeThreadNotify();

	ResumePreviousMode();


	return status;
}

NTSTATUS ReadWrite::MyReadMem(IN HANDLE ProcessId, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL){
	HANDLE hProcess = 0;
	CLIENT_ID cid = {0};
	OBJECT_ATTRIBUTES objattr = { 0 };
	NTSTATUS status;
	InitializeObjectAttributes(&objattr, 0, 0, 0, 0);
	cid.UniqueProcess = ProcessId;

	status = ZwOpenProcess(&hProcess, 0, &objattr, &cid);

	if (!NT_SUCCESS(status)) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to get process handle errcode=0x%x\n", status);

		return status;
	}




	ChangePreviousMode();


	status=Global::GetInstance()->pNtRead(hProcess, BaseAddress, Buffer, BufferLength, ReturnLength);

	if (!NT_SUCCESS(status)) {

		//err

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to read process mem! err code=0x%x\n", status);

		ResumePreviousMode();

		return status;
	}



	ResumePreviousMode();

	return status;
}

NTSTATUS ReadWrite::MyProtectMem(HANDLE ProcessId, PVOID* plpAddress, SIZE_T* pSize_t, DWORD32 dwNewProtect, PDWORD32 OldProtect) {

	CLIENT_ID cid;
	cid.UniqueProcess = ProcessId;
	cid.UniqueThread = 0;
	OBJECT_ATTRIBUTES objattr;
	memset(&objattr,0,sizeof(OBJECT_ATTRIBUTES));
	InitializeObjectAttributes(&objattr, 0, 0, 0, 0);
	HANDLE hProcess=0;
	NTSTATUS status = STATUS_SUCCESS;

	status=ZwOpenProcess(&hProcess, 0, &objattr, &cid);

	if (!NT_SUCCESS(status)) {
		//err
		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to get process handle errcode=0x%x\n",status);
		return STATUS_UNSUCCESSFUL;
	}



	ChangePreviousMode();


	status=Global::GetInstance()->pNtProtect(hProcess,plpAddress,pSize_t,dwNewProtect,OldProtect);

	if (!NT_SUCCESS(status)) {

		//err
		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to change mem attributes! errcode=0x%x\n",status);
		ResumePreviousMode();
		return STATUS_UNSUCCESSFUL;
	}


	ResumePreviousMode();

	return status;
}



bool BanThreadNotify() {

	PLONG PspNotifyEnableMask = (PLONG)Global::GetInstance()->uPspNotifyEnableMask;

	if (!MmIsAddressValid(PspNotifyEnableMask)) {
		//ERR
		KdPrint(("[OxygenDriver]err:Failed to disable thread callbacks\n"));
		return false;

	}

	//禁止线程回调
	_InterlockedAnd(PspNotifyEnableMask, 0xFFFFFFF7);
	return true;
}


bool ResumeThreadNotify() {


	PLONG PspNotifyEnableMask = (PLONG)Global::GetInstance()->uPspNotifyEnableMask;

	if (!MmIsAddressValid(PspNotifyEnableMask)) {
		//ERR
		KdPrint(("[OxygenDriver]err:Failed to enable thread callbacks\n"));
		return false;

	}

	//禁止线程回调
	_InterlockedOr(PspNotifyEnableMask, 8u);
	return true;


}


void OnWPbit(KIRQL irpl) {
	//开启CR0
	UINT64 Cr0 = __readcr0();
	Cr0 |= 0x10000;
	_enable();
	__writecr0(Cr0);
	KeLowerIrql(irpl);
}


KIRQL OffWPbit() {

	//关闭CR0
	auto irql = KeRaiseIrqlToDpcLevel();//关闭线程切换
	UINT64 Cr0 = __readcr0();
	Cr0 &= 0xfffffffffffeffff;
	__writecr0(Cr0);
	_disable();
	return irql;
}

bool WriteByMdl(HANDLE ProcessId, PVOID BaseAddress, PVOID Buffer, size_t BufferLength, PULONG ReturnLength OPTIONAL) {

	UNREFERENCED_PARAMETER(ReturnLength);

	PMDL mdl = nullptr;
	PVOID pMappedAddress = nullptr;
	KAPC_STATE apc_state;
	memset(&apc_state, 0, sizeof(KAPC_STATE));
	PEPROCESS pEprocess = nullptr;
	
	NTSTATUS status=PsLookupProcessByProcessId(ProcessId, &pEprocess);

	if (!NT_SUCCESS(status)) {
		//ERR
		KdPrint(("[OxygenDriver]err:failed to get process\n"));
		return false;

	}

	KeStackAttachProcess(pEprocess, &apc_state);

	if (!MmIsAddressValid(BaseAddress)) {
		//err
		KeUnstackDetachProcess(&apc_state);
		ObDereferenceObject(pEprocess);
		KdPrint(("[OxygenDriver]err:address invalid!\n"));
		return false;

	}

	mdl = MmCreateMdl(0, BaseAddress, BufferLength);

	if (NULL == mdl) {

		KeUnstackDetachProcess(&apc_state);
		ObDereferenceObject(pEprocess);
		KdPrint(("[OxygenDriver]err:failed to create mdl!\n"));
		return false;

	}

	//锁定页面
	MmBuildMdlForNonPagedPool(mdl);


	pMappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, 0, 0, NormalPagePriority);

	//强写
	KIRQL oldIrql = OffWPbit();

	if (!MmIsAddressValid(pMappedAddress)) {


		OnWPbit(oldIrql);
		KeUnstackDetachProcess(&apc_state);
		ObDereferenceObject(pEprocess);
		IoFreeMdl(mdl);
		KdPrint(("[OxygenDriver]err:Mapped addr within mdl err!\n"));
		return false;

	}

	__try{

		RtlCopyMemory(pMappedAddress, Buffer, BufferLength);

	}
	__except (1) {

		OnWPbit(oldIrql);
		KeUnstackDetachProcess(&apc_state);
		ObDereferenceObject(pEprocess);
		MmUnmapLockedPages(pMappedAddress, mdl);
		IoFreeMdl(mdl);
		KdPrint(("[OxygenDriver]err:Cpoy err!\n"));
		return false;

	}

	OnWPbit(oldIrql);
	MmUnmapLockedPages(pMappedAddress, mdl);
	IoFreeMdl(mdl);
	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(pEprocess);
	return true;
}





