/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#ifdef LSASS_DECRYPT
#include "../globals_sekurlsa.h"
typedef struct _KIWI_DECRYPTOR {
	DWORD cbData;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_DECRYPTOR, *PKIWI_DECRYPTOR;

NTSTATUS kuhl_m_sekurlsa_nt63_init();
NTSTATUS kuhl_m_sekurlsa_nt63_clean();
PLSA_PROTECT_MEMORY kuhl_m_sekurlsa_nt63_pLsaProtectMemory, kuhl_m_sekurlsa_nt63_pLsaUnprotectMemory;

NTSTATUS kuhl_m_sekurlsa_nt63_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
NTSTATUS kuhl_m_sekurlsa_nt63_LsaEncryptMemory(IN PVOID Buffer, IN ULONG BufferSize, IN BOOL Encrypt);
VOID WINAPI kuhl_m_sekurlsa_nt63_LsaProtectMemory (IN PVOID Buffer, IN ULONG BufferSize);
VOID WINAPI kuhl_m_sekurlsa_nt63_LsaUnprotectMemory (IN PVOID Buffer, IN ULONG BufferSize);
#endif