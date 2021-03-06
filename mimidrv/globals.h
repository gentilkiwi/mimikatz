/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include <ntifs.h>
#include <fltkernel.h>
#include <ntddk.h>
#include <aux_klib.h>
#include <ntstrsafe.h>
#include <string.h>
#include "ioctl.h"

#define POOL_TAG	'kiwi'
#define MIMIDRV		L"mimidrv"

#define kprintf(KiwiBuffer, Format, ...) (RtlStringCbPrintfExW(*(KiwiBuffer)->Buffer, *(KiwiBuffer)->szBuffer, (KiwiBuffer)->Buffer, (KiwiBuffer)->szBuffer, STRSAFE_NO_TRUNCATION, Format, __VA_ARGS__))

extern char * PsGetProcessImageFileName(PEPROCESS monProcess);
extern NTSYSAPI NTSTATUS NTAPI ZwSetInformationProcess (__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass, __in_bcount(ProcessInformationLength) PVOID ProcessInformation, __in ULONG ProcessInformationLength);
extern NTSYSAPI NTSTATUS NTAPI ZwUnloadKey(IN POBJECT_ATTRIBUTES DestinationKeyName); 

typedef struct _KIWI_BUFFER {
	size_t * szBuffer;
	PWSTR * Buffer;
} KIWI_BUFFER, *PKIWI_BUFFER;

typedef enum _KIWI_OS_INDEX {
	KiwiOsIndex_UNK		= 0,
	KiwiOsIndex_XP		= 1,
	KiwiOsIndex_2K3		= 2,
	KiwiOsIndex_VISTA	= 3,
	KiwiOsIndex_7		= 4,
	KiwiOsIndex_8		= 5,
	KiwiOsIndex_BLUE	= 6,
	KiwiOsIndex_10_1507	= 7,
	KiwiOsIndex_10_1511	= 8,
	KiwiOsIndex_10_1607	= 9,
	KiwiOsIndex_10_1703	= 10,
	KiwiOsIndex_10_1709	= 11,
	KiwiOsIndex_10_1803	= 12,
	KiwiOsIndex_10_1809	= 13,
	KiwiOsIndex_MAX		= 14,
} KIWI_OS_INDEX, *PKIWI_OS_INDEX;

#ifdef _M_IX86
#define EX_FAST_REF_MASK	0x07
#else
#define EX_FAST_REF_MASK	0x0f
#endif

#define KIWI_mask3bits(addr)	 (((ULONG_PTR) (addr)) & ~7)

KIWI_OS_INDEX KiwiOsIndex;