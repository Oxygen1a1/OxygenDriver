#include <ntifs.h>
#include <ntddk.h>
#include "Global.h"
#include "APC.h"
#include "ReadWrite.h"
#include "Injector.h"
#include "PageAttrHide.h"


#pragma warning(disable : 4100)


//


UNICODE_STRING usDevname = RTL_CONSTANT_STRING(L"\\Device\\OxygenDriver");
UNICODE_STRING usSymlink = RTL_CONSTANT_STRING(L"\\??\\OxygenDriver");


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegPath);
void DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchFuncDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchFuncCreateClose(PDEVICE_OBJECT DriverObject, PIRP Irp);
//初始化设备和符号便于通信
NTSTATUS LoadDevAndSymLink(PDRIVER_OBJECT DriverObject);
//获取本机Ntosknrl的基质
ULONG_PTR GetNtOskrnlBase();







extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath) {
	UNREFERENCED_PARAMETER(RegPath);
	return LoadDevAndSymLink(DriverObject);

}


void DriverUnload(PDRIVER_OBJECT DriverObject) {

	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&usSymlink);
	ExFreePool(Global::GetInstance());

	KdPrint(("[OxygenDriver]info:Unload Driver successly\n"));

}

NTSTATUS DispatchFuncCreateClose(PDEVICE_OBJECT DriverObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DriverObject);
	NTSTATUS status = STATUS_SUCCESS;


	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;

}



NTSTATUS DispatchFuncDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case CTL_CODE_INIT: {
		//初始化

		InitPdb* buffer=(InitPdb*)Irp->AssociatedIrp.SystemBuffer;

		if (!MmIsAddressValid(buffer)) {
			//err

			KdPrint(("[OxygenDriver]err:InitPdb system buffer err\n"));
			return STATUS_UNSUCCESSFUL;
		}

		ULONG_PTR uNtosnrlBase= GetNtOskrnlBase();

		if (!uNtosnrlBase) {
			//err
			KdPrint(("[OxygenDriver]err:failed to get ntoskrnlbase\n"));
			return STATUS_UNSUCCESSFUL;

		}



		//初始化Global
		Global::GetInstance()->uNtosnrlBase = uNtosnrlBase;
		Global::GetInstance()->pNtAlloc = (pNtAllocateVirtualMemory)(uNtosnrlBase + buffer->uRvaNtAlloc);
		Global::GetInstance()->pNtCreateThread = (pNtCreateThreadEx)(uNtosnrlBase + buffer->uRvaNtCreateThread);
		Global::GetInstance()->pNtProtect = (pNtProtectVirtualMemory)(uNtosnrlBase + buffer->uRvaNtProtect);
		Global::GetInstance()->pNtWrite = (pNtWriteVirtualMemory)(uNtosnrlBase + buffer->uRvaNtWrite);
		Global::GetInstance()->pNtRead = (pNtReadVirtualMemory)(uNtosnrlBase + buffer->uRvaNtRead);
		Global::GetInstance()->uPspNotifyEnableMask = buffer->uPspNotifyEnableMaskRva + uNtosnrlBase;
		Global::GetInstance()->uMmpfnDatabase = buffer->uRvaMmpfndatabase + uNtosnrlBase;


		Global::GetInstance()->uVadRoot = buffer->uVadRoot;
		Global::GetInstance()->uThreadPreviouMode = buffer->uThreadPreviouMode;
		Global::GetInstance()->uApcState = buffer->uApcState;
		Global::GetInstance()->uApcUserPendingAll = buffer->uUserApcPendingAll;
		Global::GetInstance()->pGetProcAddress = buffer->pGetProcAddress;
		Global::GetInstance()->pLoadLibraryA = buffer->pLoadLibraryA;
		Global::GetInstance()->pRtlAddFunctionTable = buffer->pRtlAddFunctionTable;
		Global::GetInstance()->uOriginPte = buffer->uOriginPte;
		Global::GetInstance()->uLdrFirstCall = buffer->uLdrFirstCall;

		Global::GetInstance()->fLdrInitializeThunk = buffer->fLdrInitializeThunk;
		Global::GetInstance()->fZwContinue = buffer->fZwContinue;
		Global::GetInstance()->fRtlRaiseStatus = buffer->fRtlRaiseStatus;

		Global::GetInstance()->pKeServiceDescriptorTable = buffer->pKeServiceDescriptorTable+uNtosnrlBase;


		DbgPrintEx(77, 0, "KeServiceDescriptorTable==0x%p\r\n", Global::GetInstance()->pKeServiceDescriptorTable);

		//DbgBreakPoint();

		//已经初始化过
		Global::GetInstance()->bInitPdb = 1;
		
		KdPrint(("[OxygenDriver]info:Init Success!\n"));

		KdPrint(("[OxygenDriver]info:pNtAlloc=0x%p,pNtCreateThread=0x%p,pNtProtect=0x%p,pNtWrite=0x%p,pNtRead=0x%p,pPspEnbaleNotifyMask=0x%p,uVadRoot=0x%x,uThreadPreviouMode=0x%d\n", Global::GetInstance()->pNtAlloc, Global::GetInstance()->pNtCreateThread, Global::GetInstance()->pNtProtect, Global::GetInstance()->pNtWrite, Global::GetInstance()->pNtRead, Global::GetInstance()->uPspNotifyEnableMask, Global::GetInstance()->uVadRoot, Global::GetInstance()->uThreadPreviouMode));

		KdPrint(("[OxygenDriver]info:uApcState=0x%x,uUserApcPending=0x%x\n", buffer->uApcState, buffer->uUserApcPendingAll));


#pragma warning(disable : 4838)
#pragma  warning(disable : 4309)
		//读写测试
		//char* shellcode = (char*)ExAllocatePoolWithTag(NonPagedPool, 2, 'Test');

		//shellcode[0] = 0x90;
		//shellcode[1] = 0x88;

		//WriteByMdl(reinterpret_cast<HANDLE>(9392), reinterpret_cast<PVOID>(0x000002214CCE0000), shellcode, 2, 0);



		//ExFreePool(shellcode);


		//启动线程Test


		//		HANDLE ProcessId = (HANDLE)3736;
		//		PVOID pAllocAddress = 0;
		//		size_t sAllocSize;
		//
		//
		//		NTSTATUS status=ReadWrite::MyAllocMem(ProcessId, &pAllocAddress, 0, &sAllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
		//
		//		if(!NT_SUCCESS(status)){
		//			DbgPrintEx(77, 0, "ALloc err\n");
		//			return STATUS_UNSUCCESSFUL;
		//		}
		//
		//		PVOID pAllocToWrite = ExAllocatePoolWithTag(NonPagedPool, 0x10, 'WRIE');
		//
		//#pragma warning(disable : 4309)
		//#pragma warning(disable : 4838)
		//		//死循环
		//		CHAR ShellCode[] = { 0X90, 0XEB,0XFD };
		//
		//		memcpy(pAllocToWrite, ShellCode, 3);
		//
		//
		//		status = ReadWrite::MyWriteMem(ProcessId, pAllocAddress, pAllocToWrite,0x10,0);
		//
		//
		//
		//		if (!NT_SUCCESS(status)) {
		//			DbgPrintEx(77, 0, "WRITE ERR\n");
		//			ExFreePool(pAllocToWrite);
		//			return STATUS_UNSUCCESSFUL;
		//		}
		//
		//		HANDLE hThread=0;
		//		status = ReadWrite::MyCreateThread(ProcessId, (UINT64)pAllocAddress, 0, 0, 0x1000, &hThread);
		//
		//		if (!NT_SUCCESS(status)) DbgPrintEx(77, 0, "Create Err!\n");
		//
		//
		//		KdPrint(("Hanlde=0x%x\n", hThread));
		//
		//		ExFreePool(pAllocToWrite);





		//用户APC立刻执行测试
		
		////shellcode
		////mov rcx,0
		////mov rdx,0
		////mov r8,0
		////mov r9,0
		//char ShellCode[] = { 0xB9,0X00,0X00,0X00,0X00,0XBA,0X00,0X00,0X00,0X00,0X41,0XB8,0X00,0X00,0X00,0X00,0X41,0XB9,0X00,0X00,0X00,0X00,0x48,0xB8,0x50,0xA0,0xBE,0x58, 0xF8 ,0x7F, 0x00 ,0x00,0xFF,0xE0,0xC3 };
		//
		//
		//auto bInsert = APC::InsertAndDeliverUserApc(ThreadId, ShellCode, sizeof(ShellCode), &ThreadId);
		//if (bInsert) {
		//	DbgPrintEx(77, 0, "[OxygenDriver]info:Insert Apc Success\n");
		//}


		//Dll注入测试
		Injector_x64::MmInjector_x64_BypassProtect((HANDLE)6400, L"\\??\\C:\\Users\\Administrator\\Desktop\\InjectorTest.dll",true);

		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(InitPdb);
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		
		
		return STATUS_SUCCESS;

	}
	default:
		break;
	}



	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;





}


NTSTATUS LoadDevAndSymLink(PDRIVER_OBJECT DriverObject) {

	//初始化派遣函数

	DriverObject->DriverUnload = DriverUnload;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchFuncDeviceControl;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchFuncCreateClose;

	//遍历找到Ntoskrnl
	Global::GetInstance()->uDriverSection = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

	//初始化符号链接

	PDEVICE_OBJECT pdeoj;

	NTSTATUS status= IoCreateDevice(DriverObject,0,&usDevname,FILE_DEVICE_UNKNOWN,0,0,&pdeoj);
	if (!NT_SUCCESS(status)) {
		//ERR
		KdPrint(("[OxygenDriver]Err:Failed to create device\n"));
		KdPrint(("ErrCode=0x%x", status));
		return STATUS_UNSUCCESSFUL;
	}

	status = IoCreateSymbolicLink(&usSymlink, &usDevname);

	if (!NT_SUCCESS(status)) {
		//ERR
		KdPrint(("[OxygenDriver]Err:Failed to create symbolic link\n"));
		IoDeleteDevice(pdeoj);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;

}

ULONG_PTR GetNtOskrnlBase() {

	PLIST_ENTRY pPsLoadedModuleList = *(PLIST_ENTRY*)Global::GetInstance()->uDriverSection;//这个其实是指向LIST_ENTRY的结构
	PLIST_ENTRY Next = pPsLoadedModuleList->Flink;
	UNICODE_STRING usNtoskrnl = RTL_CONSTANT_STRING(L"ntoskrnl.exe");

	if (!pPsLoadedModuleList) {

		return 0;
	}

	do {
		PLDR_DATA_TABLE_ENTRY CurrentEntry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (!CurrentEntry) {

			//err
			KdPrint(("LDR_DATA err Line:%d\n", __LINE__));
			return 0;
		}
		if (CurrentEntry->DllBase == 0) {
			//排除空
			Next = Next->Flink;
			continue;
		}
		if (wcscmp(CurrentEntry->BaseDllName.Buffer, usNtoskrnl.Buffer) == 0) {
			//find
			return (ULONG_PTR)CurrentEntry->DllBase;

		}
		Next = Next->Flink;
	} while (Next != pPsLoadedModuleList);

	KdPrint(("[OxygenDriver]err:Failed to find this kernelmodule you submit\n"));
	
	return 0;


}