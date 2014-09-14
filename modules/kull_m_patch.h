/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
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
	LONG off1;
	LONG off2;
	LONG off3;
	LONG off4;
	LONG off5;
	LONG off6;
	LONG off7;
	LONG off8;
	LONG off9;
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