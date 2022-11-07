#include "PTEHook.h"

using namespace PTEHOOK;





PteHook* PteHook::m_PteHook;

bool PTEHOOK::PteHook::fn_ptehook_hooksyscall(ULONG sysindex, ULONG_PTR TargetFunc, bool bRetOrigin)
{

	ULONG_PTR uSstBase = 0;
	UINT32 uOffset = 0;

	//新修改进去的Offset


	KdPrint(("替换的uOffset==0x%p\r\n", uOffset));
	//获取sst表 只获取非gui的ssdt
	
	if (!sst)  if (!fn_get_ssdt()) { return false; }

	//检查index

	if (sysindex > sst->NumberOfServices) {

		DbgPrintEx(77, 0, "[OyxgenDriver_SSDTHook]err:error sysindex\r\n");

		return false;
	}
	
	//将其添加到Saved里面

	if (!fn_insert_hook(sysindex)) return false;

	uSstBase = (ULONG_PTR)sst->ServiceTableBase;

	uOffset = (TargetFunc - uSstBase) * 0x10;

	KdPrint(("即将替换的Offset==0x%p\r\n", uOffset));


	//替换

	sst->ServiceTableBase[sysindex * 4] = uOffset;


	return true;
}



PteHook* PTEHOOK::PteHook::GetInstance()
{
	if (!m_PteHook) {

		m_PteHook = (PteHook*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PteHook), 'PTEH');



	}
	


	return m_PteHook;
}

//init ptes isolation
bool PTEHOOK::PteHook::fn_init_isolaiton_ptes(HANDLE ProcessId,ULONG_PTR uIsolationAddr, int PageCount)
{
	PageAttrHide::PteTable table = {0};

	//Vertify addr valid

	uIsolationAddr &= 0xfffffffffffff000;

	for (int i = 0; i < PageCount; i++) {

		if (!MmIsAddressValid((PVOID)(uIsolationAddr + PageCount * 0x1000))) {
			DbgPrintEx(77, 0, "[OxygenDriver]err:summit address is invalid\r\n");

			return false;
		}


	}



	//Alloc a NonPaged mem and get it's physical addr , full it original ptes

	for (int i = 0; i < PageCount; i++) {

		table.pLineAddr = uIsolationAddr + i * 0x1000;

		PageAttrHide::GetLineAddrPteTable(&table);

		PULONG_PTR Ptes = (PULONG_PTR)table.Pte;

		if (!MmIsAddressValid(Ptes)) {

			DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to change ptes\r\n");
			
			return false;
		}

		//alloc a nonpaged mm size of 0x1000 * 4kb ==0x4000kb 16mb
		if(!pNonPagedMm) pNonPagedMm = ExAllocatePoolWithTag(NonPagedPool, MAX_PAGES_COUNT_NONPAGEDMM, 'NONP');



	}

	return false;
}

bool PTEHOOK::PteHook::fn_get_ssdt()
{
	//
	this->sst = (PSYSTEM_SERVICE_TABLE)Global::GetInstance()->pKeServiceDescriptorTable;

	return true;
}

bool PTEHOOK::PteHook::fn_insert_hook(ULONG sysindex)
{
	for (int i = 0; i < MAX_HOOK_COUNT; i++) {

		if (this->ArrHookSavedInfo[i].sysindex == 0) {
			//没被占用
			this->ArrHookSavedInfo[i].sysindex = sysindex;
			this->ArrHookSavedInfo[i].OriginAddress = fn_get_syscall_by_index(sysindex);

			return true;

		}



	}


	DbgPrintEx(77, 0, "[OxygenDriver_SSDTHook]err:there is no space for new hook\r\n");

	return false;
}

ULONG_PTR PTEHOOK::PteHook::fn_get_syscall_by_index(ULONG sysindex)
{
	UINT32 uOffset = (this->sst->ServiceTableBase[sysindex * 4] / 0x10);
	

	KdPrint(("uOffset=0x%x\r\n",uOffset));


	return ((ULONG_PTR)uOffset+(ULONG_PTR)this->sst->ServiceTableBase);
}



