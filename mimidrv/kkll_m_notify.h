/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kkll_m_memory.h"
#include "kkll_m_modules.h"

#define OBJECT_HASH_TABLE_SIZE	37
#define CM_REG_MAX_CALLBACKS	100

typedef struct _KKLL_M_NOTIFY_CALLBACK {
#if defined(_M_IX86)
	ULONG unk0;
#endif
	PVOID * callback;
} KKLL_M_NOTIFY_CALLBACK, *PKKLL_M_NOTIFY_CALLBACK;

typedef struct _OBJECT_DIRECTORY_ENTRY {
	struct	_OBJECT_DIRECTORY_ENTRY *	ChainLink;
	PVOID								Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY {
	POBJECT_DIRECTORY_ENTRY		HashBuckets[OBJECT_HASH_TABLE_SIZE];
	/* ... */
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef struct _OBJECT_CALLBACK_ENTRY {
	LIST_ENTRY					CallbackList;
	OB_OPERATION				Operations;
	ULONG Active;
	/*OB_HANDLE*/ PVOID Handle;
	POBJECT_TYPE				ObjectType;
	POB_PRE_OPERATION_CALLBACK	PreOperation;
	POB_POST_OPERATION_CALLBACK	PostOperation;
	/* ... */
} OBJECT_CALLBACK_ENTRY, *POBJECT_CALLBACK_ENTRY;

typedef NTSTATUS	(* PPSSETCREATEPROCESSNOTIFYROUTINEEX)	( __in PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, __in BOOLEAN Remove);
//typedef VOID (* POBUNREGISTERCALLBACKS) (__in PVOID RegistrationHandle);

NTSTATUS kkll_m_notify_list_thread(PKIWI_BUFFER outBuffer);
NTSTATUS kkll_m_notify_list_process(PKIWI_BUFFER outBuffer);
NTSTATUS kkll_m_notify_list_image(PKIWI_BUFFER outBuffer);
NTSTATUS kkll_m_notify_list_reg(PKIWI_BUFFER outBuffer);
NTSTATUS kkll_m_notify_list_object(PKIWI_BUFFER outBuffer);
NTSTATUS kkll_m_notify_desc_object_callback(POBJECT_CALLBACK_ENTRY pCallbackEntry, PKIWI_BUFFER outBuffer);

NTSTATUS kkll_m_notify_list(PKIWI_BUFFER outBuffer, PKKLL_M_MEMORY_GENERIC generics, SIZE_T cbGenerics, PUCHAR * ptr, PULONG pRoutineMax);
NTSTATUS kkll_m_notify_search(PKKLL_M_MEMORY_GENERIC generics, SIZE_T cbGenerics, PUCHAR * ptr, PULONG pRoutineMax, PKKLL_M_MEMORY_OFFSETS * pOffsets);