#pragma once 
#include <ntifs.h>
#include <ntddk.h>
//h


namespace APC{

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment

}KAPC_ENVIRONMENT;

typedef VOID(*PKRUNDOWN_ROUTINE) (IN struct _KAPC* Apc);
typedef VOID(*PKNORMAL_ROUTINE)(IN PVOID NormalContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2);
typedef VOID(*PKKERNEL_ROUTINE)(PRKAPC Apc,PKNORMAL_ROUTINE* pNormalRoutine, PVOID* pNormalContext, PVOID* pSystemArgument1, PVOID* pSystemArgument2);


typedef VOID (*pKeInitializeApc)(__out PRKAPC Apc,__in PRKTHREAD Thread,__in KAPC_ENVIRONMENT Environment,__in PKKERNEL_ROUTINE KernelRoutine,__in_opt PKRUNDOWN_ROUTINE RundownRoutine,__in_opt PKNORMAL_ROUTINE NormalRoutine,__in_opt KPROCESSOR_MODE ApcMode,__in_opt PVOID NormalContext);
typedef BOOLEAN (*pKeInsertQueueApc)(__inout PRKAPC Apc,__in_opt PVOID SystemArgument1,__in_opt PVOID SystemArgument2,__in KPRIORITY Increment);


//×¨ÓÃÏû³ý
VOID RunDownApcRoutine(PKAPC Apc);
VOID KernelRoutineForUser(PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SysArg1, PVOID* SysArg2);



BOOLEAN InsertAndDeliverKernelApc(PKAPC Apc, PKTHREAD Thread, KAPC_ENVIRONMENT Environment, PKKERNEL_ROUTINE KernelRoutine, PKRUNDOWN_ROUTINE RundownRoutine, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SysArg1, PVOID SysArg2);
BOOLEAN InsertAndDeliverUserApc(HANDLE ThreadId, CHAR* ShellCode, size_t ShellSize, PVOID NormalContext);
//
}