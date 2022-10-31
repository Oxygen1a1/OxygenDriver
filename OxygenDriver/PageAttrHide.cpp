#include "PageAttrHide.h"
#include <ntifs.h>
#include <intrin.h>

using namespace PageAttrHide;

//ͨ��ҳ���Զ�λ��ȷ��PTEBASE
//����PML4E,�ҵ���ָ��CR3���±� ����39λ | 0xFFFF 0000 0000 0000����PTEBASE
//Ϊʲô����?
//���������ܸ��� Ҫ���Ȱ���ӳ���˼��
//���PML4E 
ULONG_PTR PageAttrHide::GetPteBase()
{
	UINT64 cr3=__readcr3();

	PHYSICAL_ADDRESS _cr3;

	_cr3.QuadPart = cr3;

	UINT64* pml4e_va=(UINT64*)MmGetVirtualForPhysical(_cr3);

	//DbgBreakPoint();

	//��ʵCr3��������PML4E��ָ��,������ΪWindowsΪ�˷���,������PML4E����������cr3
	//�����ҵ�PML4Eָ��cr3��index
	UINT64 index = 0;
	//512
	for (int i = 0; i < 512; i++) {

		UINT64 Pte = *(pml4e_va+i);

		Pte &= 0xFFFFFFFFF000;

		if (Pte == cr3) {
			//�ҵ�PML4E Index ֱ������39λ����PTEBASE

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
	//���Ȼ�ȡPteBase
	ULONG_PTR PteBase=GetPteBase();

	UINT64 LineAddr = Table->pLineAddr;

	//>>12�ڼ���Pte  <<3����8���ֽ�

	PteBase &= 0x0000FFFFFFFFFFFF; //�����ǰ16λ

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
void PageAttrHide::ChangeVadAttributes(ULONG_PTR uAddr,UINT32 Attributes)
{



	UINT64 phPteIndex;
	PteTable Table;
	Table.pLineAddr = uAddr;
	ULONG_PTR uOrginPte = Global::GetInstance()->uOriginPte;



	//�п����Ҳ���
	if(!uOrginPte)
	uOrginPte = 0x10;

	//����ط�������

	DbgBreakPoint();

	ULONG_PTR MmPfnDataBase = *(ULONG_PTR*)(Global::GetInstance()->uMmpfnDatabase);




	//x64 mmpfn ��С 0x30
	//OriginalPte ��0x28ƫ�ƴ�

	GetLineAddrPteTable(&Table);

	//��ȡ�����ַ
	phPteIndex = *(UINT64*)(Table.Pte);


	//��ȡ�����ַ����
	phPteIndex &= 0x0000fffffffff000;
	phPteIndex =phPteIndex>> 12;

	//����ԭ��PTE
	MMPTE_SOFTWARE* pOriginPte = (MMPTE_SOFTWARE*)(MmPfnDataBase + uMmpfnSize * phPteIndex + uOrginPte);
	//�޸�����
	pOriginPte->Protection |= Attributes;

	


}
