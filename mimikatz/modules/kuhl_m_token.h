/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_token.h"
#include "../modules/kull_m_net.h"

const KUHL_M kuhl_m_token;

typedef struct _KUHL_M_TOKEN_ELEVATE_DATA {
	PSID pSid;
	PCWSTR pUsername;
	DWORD tokenId;
	BOOL elevateIt;
} KUHL_M_TOKEN_ELEVATE_DATA, *PKUHL_M_TOKEN_ELEVATE_DATA;

void kuhl_m_token_displayAccount(HANDLE hToken);

NTSTATUS kuhl_m_token_whoami(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_elevate(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_revert(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_kdup(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_token_list_or_elevate(int argc, wchar_t * argv[], BOOL elevate);
BOOL CALLBACK kuhl_m_token_list_or_elevate_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);