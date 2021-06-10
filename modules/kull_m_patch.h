/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kull_m_memory.h"
#include "kull_m_service.h"
#include "kull_m_process.h"

typedef NTSTATUS (* PKULL_M_PATCH_CALLBACK) (int argc, wchar_t * args[]);

typedef struct _KULL_M_PATCH_PATTERN {
	DWORD Length;
	BYTE *Pattern;
} KULL_M_PATCH_PATTERN, *PKULL_M_PATCH_PATTERN;

typedef struct _KULL_M_PATCH_OFFSETS {
	LONG off0;
#if defined(_M_ARM64)
	LONG armOff0;
#endif
	LONG off1;
#if defined(_M_ARM64)
	LONG armOff1;
#endif
	LONG off2;
#if defined(_M_ARM64)
	LONG armOff2;
#endif
	LONG off3;
#if defined(_M_ARM64)
	LONG armOff3;
#endif
	LONG off4;
#if defined(_M_ARM64)
	LONG armOff4;
#endif
	LONG off5;
#if defined(_M_ARM64)
	LONG armOff5;
#endif
	LONG off6;
#if defined(_M_ARM64)
	LONG armOff6;
#endif
	LONG off7;
#if defined(_M_ARM64)
	LONG armOff7;
#endif
	LONG off8;
#if defined(_M_ARM64)
	LONG armOff8;
#endif
	LONG off9;
#if defined(_M_ARM64)
	LONG armOff9;
#endif
} KULL_M_PATCH_OFFSETS, *PKULL_M_PATCH_OFFSETS;

typedef struct _KULL_M_PATCH_GENERIC {
	DWORD MinBuildNumber;
	KULL_M_PATCH_PATTERN Search;
	KULL_M_PATCH_PATTERN Patch;
	KULL_M_PATCH_OFFSETS Offsets;
} KULL_M_PATCH_GENERIC, *PKULL_M_PATCH_GENERIC;

typedef struct _KULL_M_PATCH_MULTIPLE {
	KULL_M_PATCH_PATTERN Search;
	KULL_M_PATCH_PATTERN Patch;
	LONG Offset;
	KULL_M_MEMORY_ADDRESS AdressOfPatch;
	DWORD OldProtect;
	KULL_M_MEMORY_ADDRESS LocalBackup;
} KULL_M_PATCH_MULTIPLE, *PKULL_M_PATCH_MULTIPLE;

BOOL kull_m_patch(PKULL_M_MEMORY_SEARCH sMemory, PKULL_M_MEMORY_ADDRESS pPattern, SIZE_T szPattern, PKULL_M_MEMORY_ADDRESS pPatch, SIZE_T szPatch, LONG offsetOfPatch, PKULL_M_PATCH_CALLBACK pCallBackBeforeRestore, int argc, wchar_t * args[], NTSTATUS * pRetCallBack);
PKULL_M_PATCH_GENERIC kull_m_patch_getGenericFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber);
BOOL kull_m_patch_genericProcessOrServiceFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PCWSTR processOrService, PCWSTR moduleName, BOOL isService);