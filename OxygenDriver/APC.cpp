#include "Global.h"
#include "APC.h"
#include "ReadWrite.h"

using namespace APC;


//����δ���õ��β�
#pragma  warning(disable : 4100)

VOID APC::RunDownApcRoutine(PKAPC Apc) {


	//����ռ�
	ExFreePool(Apc);

}



VOID APC::KernelRoutineForUser(PRKAPC Apc, PKNORMAL_ROUTINE* pNormalRoutine, PVOID* pNormalContext, PVOID* pSystemArgument1, PVOID* pSystemArgument2) {
	//�����û�APCִ��ʱ��
	//ʲô������
	DbgPrintEx(77, 0, "KernelRoutine done,NormalRoutine==0x%p\n", *pNormalRoutine);


}


BOOLEAN APC::InsertAndDeliverKernelApc(PKAPC Apc, PKTHREAD Thread, KAPC_ENVIRONMENT Environment, PKKERNEL_ROUTINE KernelRoutine, PKRUNDOWN_ROUTINE RundownRoutine, PKNORMAL_ROUTINE NormalRoutine,  PVOID NormalContext, PVOID SysArg1, PVOID SysArg2) {
	KPROCESSOR_MODE ApcMode = 0;//KernelApc

	//��ȡKeInitlialzeApc��KeInsertQueueApc
	UNICODE_STRING usKeInitializeApc = RTL_CONSTANT_STRING(L"KeInitializeApc");
	UNICODE_STRING usKeInsertQueueApc = RTL_CONSTANT_STRING(L"KeInsertQueueApc");


	pKeInitializeApc KeInitializeApc = (pKeInitializeApc)MmGetSystemRoutineAddress(&usKeInitializeApc);
	pKeInsertQueueApc KeInsertQueueApc = (pKeInsertQueueApc)MmGetSystemRoutineAddress(&usKeInsertQueueApc);


	KeInitializeApc(Apc, Thread, Environment, KernelRoutine, RundownRoutine, NormalRoutine, ApcMode, NormalContext);
	BOOLEAN bOk=KeInsertQueueApc(Apc, SysArg1, SysArg2,0);

	if (!bOk) {
		//err

		DbgPrintEx(77, 0, "[OxygenDriver]err:Insert ApcList Err!\n");
		ExFreePool(Apc);
		return 0;
	}

	return bOk;

}


BOOLEAN APC::InsertAndDeliverUserApc( HANDLE ThreadId,CHAR* ShellCode,size_t ShellSize,PVOID NormalContext) {
	
	//DbgBreakPoint();
	//�������APC����ִ�� ��Ҫ�����ʱ���޸�ApcUserPending | 2����
	PKTHREAD Thread;
	PKAPC Apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'APC');
	memset(Apc, 0, sizeof(KAPC));
	KPROCESSOR_MODE ApcMode = 1;//UserApc
	auto Environment = OriginalApcEnvironment;
	PEPROCESS Process;
	PKAPC_STATE ApcState;
	NTSTATUS status = STATUS_SUCCESS;
	size_t size = 0x1000;
	PVOID NormalRoutine=0;
	DWORD32 dwOldProtection = 0;


	status=PsLookupThreadByThreadId(ThreadId, &Thread);

	if (!NT_SUCCESS(status)) {

		//err
		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to get thread\n");

		return false;

	}



	//��ȡKeInitlialzeApc��KeInsertQueueApc
	UNICODE_STRING usKeInitializeApc = RTL_CONSTANT_STRING(L"KeInitializeApc");
	UNICODE_STRING usKeInsertQueueApc = RTL_CONSTANT_STRING(L"KeInsertQueueApc");


	pKeInitializeApc KeInitializeApc = (pKeInitializeApc)MmGetSystemRoutineAddress(&usKeInitializeApc);
	pKeInsertQueueApc KeInsertQueueApc = (pKeInsertQueueApc)MmGetSystemRoutineAddress(&usKeInsertQueueApc);

	if (!KeInitializeApc || !KeInsertQueueApc) {
		//err
		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to Getsystem routine!\n");

	}

	//��ȡ�̵߳Ľ���


	ULONG_PTR uApcState = Global::GetInstance()->uApcState;
	ApcState = (PKAPC_STATE)((ULONG_PTR)Thread + uApcState);
	


	if (!uApcState) {
		DbgPrintEx(77, 0, "[OxygenDriver]err:Apcstate offset err!\n");
		return false;
	}


	if (!MmIsAddressValid(ApcState)) {

		//err
		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to get process from Apcstate\n");
		return false;
	}

	Process = ApcState->Process;

	//��ȡPID ����͵�˸���  û��Pdb��

	HANDLE ProcessId = *(PHANDLE)((ULONG_PTR)Process + 0x440);


	//����һ���ڴ�
	
	//��Ҫ����һ��ֻ��ִ���ڴ�,�����д���ܻᱻ��

	status = ReadWrite::MyAllocMem(ProcessId, &NormalRoutine,0,&size,MEM_COMMIT,PAGE_EXECUTE,nullptr);

	if (!NT_SUCCESS(status)) return false;

	
	//��ShellCodeд�뵽������ڴ�
	
	//��Ϊ֮ǰ�����ԭ�� �����޸�����ط���ҳ������ ������д


	status = ReadWrite::MyProtectMem(ProcessId, &NormalRoutine, &size, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	status = ReadWrite::MyWriteMem(ProcessId, NormalRoutine, ShellCode, ShellSize, NULL);

	//���޸Ļ�ȥԭ����ҳ�汣������
	status = ReadWrite::MyProtectMem(ProcessId, &NormalRoutine, &size, dwOldProtection, &dwOldProtection);

	if (!NT_SUCCESS(status)) return false;

	KeInitializeApc(Apc, Thread, Environment, KernelRoutineForUser, RunDownApcRoutine, (APC::PKNORMAL_ROUTINE)NormalRoutine, ApcMode, NormalContext);
	
	BOOLEAN bOk = KeInsertQueueApc(Apc, 0, 0, 0);

	if (!bOk) {
		//err

		DbgPrintEx(77, 0, "[OxygenDriver]err:Insert ApcList Err!\n");
		ExFreePool(Apc);
		return 0;
	}



	INT64* UserApcPendingAll = (INT64*)((ULONG_PTR)Thread + Global::GetInstance()->uApcUserPendingAll + Global::GetInstance()->uApcState);

	*UserApcPendingAll |= 2;//UserApcPending��λ;APC���̿���ִ��
	
	return bOk;
}

