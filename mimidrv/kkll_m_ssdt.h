/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kkll_m_modules.h"
#include "kkll_m_memory.h"

typedef struct _SERVICE_DESCRIPTOR_TABLE {
#if defined(_M_IX86)
	PVOID	*ServiceTable;
#elif defined(_M_X64)
	LONG	*OffsetToService;
#endif
	PULONG	CounterTable;
	ULONG	TableSize;
	PUCHAR	ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

#if defined(_M_IX86)
	extern PSERVICE_DESCRIPTOR_TABLE	KeServiceDescriptorTable;
#elif defined(_M_X64)
	PSERVICE_DESCRIPTOR_TABLE			KeServiceDescriptorTable;
	NTSTATUS kkll_m_ssdt_getKeServiceDescriptorTable();
#endif

NTSTATUS kkll_m_ssdt_list(PKIWI_BUFFER outBuffer);