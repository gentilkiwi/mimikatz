/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kwindbg.h"
#include <bcrypt.h>

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

typedef struct _KIWI_BCRYPT_KEY8 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	PVOID unk4;	// before, align in x64
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY8, *PKIWI_BCRYPT_KEY8;

typedef struct _KIWI_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2; 
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, *PKIWI_BCRYPT_KEY81;

typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, *PKIWI_BCRYPT_HANDLE_KEY;

typedef struct _KIWI_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} KIWI_BCRYPT_GEN_KEY, *PKIWI_BCRYPT_GEN_KEY;

NTSTATUS kuhl_m_sekurlsa_nt6_init();
NTSTATUS kuhl_m_sekurlsa_nt6_clean();

NTSTATUS kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory();
VOID kuhl_m_sekurlsa_nt6_LsaCleanupProtectedMemory();
VOID WINAPI kuhl_m_sekurlsa_nt6_LsaUnprotectMemory (IN PVOID Buffer, IN ULONG BufferSize);

NTSTATUS kuhl_m_sekurlsa_nt6_acquireKeys(ULONG_PTR pInitializationVector, ULONG_PTR phAesKey, ULONG_PTR ph3DesKey);
BOOL kuhl_m_sekurlsa_nt6_acquireKey(ULONG_PTR phKey, PKIWI_BCRYPT_GEN_KEY pGenKey);