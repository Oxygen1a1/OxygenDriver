#pragma once
#include "Global.h"

#define MM_ZERO_ACCESS         0  // this value is not used.
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4  // bit 2 is set if this is writable.
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7

#define MM_NOCACHE            0x8
#define MM_GUARD_PAGE         0x10
#define MM_DECOMMIT           0x10   // NO_ACCESS, Guard page
#define MM_NOACCESS           0x18   // NO_ACCESS, Guard_page, nocache.
#define MM_UNKNOWN_PROTECTION 0x100  // bigger than 5 bits!

namespace PageAttrHide{


	const ULONG_PTR uMmpfnSize = 0x30;

	struct PteTable
	{
		//传入的线性地址
		ULONG_PTR pLineAddr;

		//获取的
		ULONG_PTR Pte;
		ULONG_PTR Pde;
		ULONG_PTR PdPte;
		ULONG_PTR Pml4e;

	};

	//软件解析PTE
	typedef struct _MMPTE_SOFTWARE              // 13 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/     UINT64       Valid : 1;                 // 0 BitPosition                   
		/*0x000*/     UINT64       PageFileReserved : 1;      // 1 BitPosition                   
		/*0x000*/     UINT64       PageFileAllocated : 1;     // 2 BitPosition                   
		/*0x000*/     UINT64       ColdPage : 1;              // 3 BitPosition                   
		/*0x000*/     UINT64       SwizzleBit : 1;            // 4 BitPosition                   
		/*0x000*/     UINT64       Protection : 5;            // 5 BitPosition                   
		/*0x000*/     UINT64       Prototype : 1;             // 10 BitPosition                  
		/*0x000*/     UINT64       Transition : 1;            // 11 BitPosition                  
		/*0x000*/     UINT64       PageFileLow : 4;           // 12 BitPosition                  
		/*0x000*/     UINT64       UsedPageTableEntries : 10; // 16 BitPosition                  
		/*0x000*/     UINT64       ShadowStack : 1;           // 26 BitPosition                  
		/*0x000*/     UINT64       Unused : 5;                // 27 BitPosition                  
		/*0x000*/     UINT64       PageFileHigh : 32;         // 32 BitPosition                  
	}MMPTE_SOFTWARE, * PMMPTE_SOFTWARE;

	//硬件解析PTE

	typedef struct _MMPTE_HARDWARE            // 18 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/     UINT64       Valid : 1;               // 0 BitPosition                   
		/*0x000*/     UINT64       Dirty1 : 1;              // 1 BitPosition                   
		/*0x000*/     UINT64       Owner : 1;               // 2 BitPosition                   
		/*0x000*/     UINT64       WriteThrough : 1;        // 3 BitPosition                   
		/*0x000*/     UINT64       CacheDisable : 1;        // 4 BitPosition                   
		/*0x000*/     UINT64       Accessed : 1;            // 5 BitPosition                   
		/*0x000*/     UINT64       Dirty : 1;               // 6 BitPosition                   
		/*0x000*/     UINT64       LargePage : 1;           // 7 BitPosition                   
		/*0x000*/     UINT64       Global : 1;              // 8 BitPosition                   
		/*0x000*/     UINT64       CopyOnWrite : 1;         // 9 BitPosition                   
		/*0x000*/     UINT64       Unused : 1;              // 10 BitPosition                  
		/*0x000*/     UINT64       Write : 1;               // 11 BitPosition                  
		/*0x000*/     UINT64       PageFrameNumber : 36;    // 12 BitPosition                  
		/*0x000*/     UINT64       ReservedForHardware : 4; // 48 BitPosition                  
		/*0x000*/     UINT64       ReservedForSoftware : 4; // 52 BitPosition                  
		/*0x000*/     UINT64       WsleAge : 4;             // 56 BitPosition                  
		/*0x000*/     UINT64       WsleProtection : 3;      // 60 BitPosition                  
		/*0x000*/     UINT64       NoExecute : 1;           // 63 BitPosition                  
	}MMPTE_HARDWARE, * PMMPTE_HARDWARE;


	ULONG_PTR GetPteBase();
	void GetLineAddrPteTable(_Inout_ PteTable* Table);
	//改变0x1000范围内线性地址的VAD属性
	//修改原型PTE, 不影响真正的PTE,但是无法通过API读写执行检查
	void  ChangeVadAttributes(ULONG_PTR uAddr, UINT32 Attributes, HANDLE ProcessId);



}