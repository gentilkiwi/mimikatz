/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

typedef struct _KKLL_M_MEMORY_PATTERN {
	DWORD Length;
	PUCHAR Pattern;
} KKLL_M_MEMORY_PATTERN, *PKKLL_M_MEMORY_PATTERN;

typedef struct _KKLL_M_MEMORY_OFFSETS {
	LONG off0;
	LONG off1;
	LONG off2;
	LONG off3;
	LONG off4;
	LONG off5;
	LONG off6;
	LONG off7;
	LONG off8;
	LONG off9;
} KKLL_M_MEMORY_OFFSETS, *PKKLL_M_MEMORY_OFFSETS;

typedef struct _KKLL_M_MEMORY_GENERIC {
	KIWI_OS_INDEX OsIndex;
	KKLL_M_MEMORY_PATTERN Search;
	PWCHAR start;
	PWCHAR end;
	KKLL_M_MEMORY_OFFSETS Offsets;
} KKLL_M_MEMORY_GENERIC, *PKKLL_M_MEMORY_GENERIC;

NTSTATUS kkll_m_memory_search(const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const UCHAR *pattern, PUCHAR *addressePattern, SIZE_T longueur);
NTSTATUS kkll_m_memory_genericPointerSearch(PUCHAR *addressePointeur, const PUCHAR adresseBase, const PUCHAR adresseMaxMin, const UCHAR *pattern, SIZE_T longueur, LONG offsetTo);

PKKLL_M_MEMORY_GENERIC kkll_m_memory_getGenericFromBuild(PKKLL_M_MEMORY_GENERIC generics, SIZE_T cbGenerics);
NTSTATUS kkll_m_memory_vm_read(PVOID Dest, PVOID From, DWORD Size);
NTSTATUS kkll_m_memory_vm_write(PVOID Dest, PVOID From, DWORD Size);
NTSTATUS kkll_m_memory_vm_alloc(DWORD Size, PVOID *Addr);
NTSTATUS kkll_m_memory_vm_free(PVOID Addr);