/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals_sekurlsa.h"
#include "../modules/kull_m_crypto_sk.h"
#include "kuhl_m_sekurlsa.h"

typedef struct _KEYLIST_ENTRY {
	LIST_ENTRY navigator;
	BYTE key[32];
	DOUBLE entropy;
} KEYLIST_ENTRY, *PKEYLIST_ENTRY;

BOOL kuhl_m_sekurlsa_sk_candidatekey_add(BYTE key[32], DOUBLE entropy);
void kuhl_m_sekurlsa_sk_candidatekey_delete(PKEYLIST_ENTRY entry);
void kuhl_m_sekurlsa_sk_candidatekey_descr(PKEYLIST_ENTRY entry);
void kuhl_m_sekurlsa_sk_candidatekeys_delete();
void kuhl_m_sekurlsa_sk_candidatekeys_descr();

DWORD kuhl_m_sekurlsa_sk_search(PBYTE data, DWORD size, BOOL light);
DWORD kuhl_m_sekurlsa_sk_search_file(LPCWSTR filename);

NTSTATUS kuhl_m_sekurlsa_sk_bootKey(int argc, wchar_t* argv[]);
BOOL kuhl_m_sekurlsa_sk_tryDecode(PLSAISO_DATA_BLOB blob, PBYTE *output, DWORD *cbOutput);