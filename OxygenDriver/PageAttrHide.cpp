#include "PageAttrHide.h"
#include <ntifs.h>
#include <intrin.h>

using namespace PageAttrHide;

//通过页表自定位来确定PTEBASE
//遍历PML4E,找到其指向CR3的下标 左移39位 | 0xFFFF 0000 0000 0000就是PTEBASE
//为什么这样?
//解释起来很复杂 要首先按照映射的思想
//最后到PML4E 
ULONG_PTR PageAttrHide::GetPteBase()
{
	UINT64 cr3=__readcr3();

	PHYSICAL_ADDRESS _cr3;

	_cr3.QuadPart = cr3;

	UINT64* pml4e_va=(UINT64*)MmGetVirtualForPhysical(_cr3);

	//DbgBreakPoint();

	//其实Cr3本质上是PML4E的指针,但是因为Windows为了方便,就在这PML4E数组里面有cr3
	//所以找到PML4E指向cr3的index
	UINT64 index = 0;
	//512
	for (int i = 0; i < 512; i++) {

		UINT64 Pte = *(pml4e_va+i);

		Pte &= 0xFFFFFFFFF000;

		if (Pte == cr3) {
			//找到PML4E Index 直接左移39位就是PTEBASE

			index = i;

			DbgPrintEx(77, 0, "Num==0x%d", i);

			break;
		}

		//DbgPrintEx(77, 0, "PML4E Phyaddr:0x%x cr3=0x%x\r\n", Pte,cr3);

	}

	if (index == 0) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:fatal err, cr3 err\r\n");

		return 0;
	}


	UINT64 PteBase =  (index + 0x1FFFE00) << 39;

	//DbgPrintEx(77, 0, "[OxygenDriver]info: PteBase=0x%p\r\n", PteBase);

	return PteBase;
}

void PageAttrHide::GetLineAddrPteTable(_Inout_ PteTable* Table)
{
	//首先获取PteBase
	ULONG_PTR PteBase=GetPteBase();

	UINT64 LineAddr = Table->pLineAddr;

	//>>12第几个Pte  <<3代表8个字节

	PteBase &= 0x0000FFFFFFFFFFFF; //先清除前16位

	Table->Pte = ((LineAddr >> 12)<<3) + PteBase;

	Table->Pde = ((Table->Pte >> 12) << 3) + PteBase;

	Table->PdPte = ((Table->Pde >> 12) << 3) + PteBase;

	Table->Pml4e = ((Table->PdPte >> 12) << 3) + PteBase;

	Table->Pte |= 0xFFFF000000000000;

	Table->Pde |= 0xFFFF000000000000;

	Table->PdPte |= 0xFFFF000000000000;

	Table->Pml4e |= 0xFFFF000000000000;

	//DbgPrintEx(77, 0, "vPte=0x%p,vPde=0x%p,vPdpte=0x%p,vPml4e=0x%p\r\n", Table->Pte, Table->Pde, Table->PdPte, Table->Pml4e);

}
#pragma warning(disable : 4100)
#pragma warning(disable : 4189)
void PageAttrHide::ChangeVadAttributes(ULONG_PTR uAddr,UINT32 Attributes,HANDLE ProcessId)
{



	UINT64 phPteIndex;
	PteTable Table;
	Table.pLineAddr = uAddr;
	ULONG_PTR uOrginPte = Global::GetInstance()->uOriginPte;
	PEPROCESS Process = 0;
	KAPC_STATE Apc = { 0 };

	//修改进程要进行挂靠
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {

		DbgPrintEx(77, 0, "[OxygenDriver]err:Failed to get process to change page attributes\r\n");

		return;
	}

	
	KeStackAttachProcess(Process, &Apc);

	//有可能找不到
	if(!uOrginPte)
	uOrginPte = 0x10;

	//这个地方出错了



	ULONG_PTR MmPfnDataBase = *(ULONG_PTR*)(Global::GetInstance()->uMmpfnDatabase);




	//x64 mmpfn 大小 0x30
	//OriginalPte 在0x28偏移处

	GetLineAddrPteTable(&Table);



	//获取物理地址
	phPteIndex = *(UINT64*)(Table.Pte);


	//获取物理地址索引
	phPteIndex &= 0x0000fffffffff000;
	phPteIndex =phPteIndex>> 12;

	//解析原型PTE
	MMPTE_SOFTWARE* pOriginPte = (MMPTE_SOFTWARE*)(MmPfnDataBase + uMmpfnSize * phPteIndex + uOrginPte);
	//修改属性
	pOriginPte->Protection = Attributes;

	
	KeUnstackDetachProcess(&Apc);

}
