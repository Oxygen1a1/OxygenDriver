#pragma once
#include "PageAttrHide.h"
#include "Global.h"

namespace PTEHOOK{

	typedef struct _HookSavedInfo {

		ULONG sysindex=0;

		ULONG_PTR OriginAddress=0;


	}HookSavedInfo,*pHookSavedInfo;




	//SSDT�ṹ
	typedef struct _SYSTEM_SERVICE_TABLE {
		PLONG  		ServiceTableBase;
		PVOID  		ServiceCounterTableBase;
		ULONGLONG  	NumberOfServices;
		PVOID  		ParamTableBase;
	} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;


class PteHook {
public:
	//cpp�������ģʽ
	

	bool fn_ptehook_hooksyscall(ULONG sysindex, ULONG_PTR TargetFunc,bool bRetOrigin=true);


	void fn_ptehook_resumehooksyscall(ULONG sysindex);

	//bool fn_ptehook_hookanyaddr(ULONG_PTR HookOrigin,ULONG_PTR HookTarget,bool IsRetOrigin)

	static PteHook* GetInstance();


private:


#define  MAX_HOOK_COUNT 100

#define MAX_PAGES_COUNT_NONPAGEDMM 0x1000

	bool fn_init_isolaiton_ptes(HANDLE ProcessId,ULONG_PTR uIsolationAddr,int PageCount);

	//��ȡSST����Ա����
	bool fn_get_ssdt();

	//���뵽HookInfo����ָ�
	bool fn_insert_hook(ULONG sysindex);

	ULONG_PTR fn_get_syscall_by_index(ULONG sysindex);

	//SST��

	PSYSTEM_SERVICE_TABLE sst=0;

	//Hook��SsdtHook����
	HookSavedInfo  ArrHookSavedInfo[MAX_HOOK_COUNT];

	//�߼�������һ��1000ҳ�ķǷ�ҳ�ڴ� Ȼ���ø���Ա������¼��ǰʹ���˶���ҳ��

	UINT32 uUsedCount = 0;

	PVOID pNonPagedMm = 0;

	static PteHook* m_PteHook;




};


}



