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
};

