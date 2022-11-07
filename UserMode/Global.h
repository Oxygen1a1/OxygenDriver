#pragma once

#define CTL_CODE_INIT CTL_CODE(0x8000,0x801,0,0)

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
	ULONG_PTR pLoadLibraryA = 0;
	ULONG_PTR pGetProcAddress = 0;
	//x64专属
	ULONG_PTR pRtlAddFunctionTable = 0;

	//因为是在对方Hook里面 所以把LdrInitializeThunk的第一个Call地址传一下
	ULONG_PTR uLdrFirstCall = 0;
	ULONG_PTR pKeServiceDescriptorTable = 0;

};

