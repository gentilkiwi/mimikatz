/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_token.h"
#include "../modules/kull_m_net.h"
#include "kuhl_m_process.h"

const KUHL_M kuhl_m_token;

//typedef enum _KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER {
//	TypeFree,
//	TypeAnonymous,
//	TypeIdentity,
//	TypeDelegation,
//	TypeImpersonate,
//	TypePrimary,
//} KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER, *PKUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER;

typedef struct _KUHL_M_TOKEN_ELEVATE_DATA {
	PSID pSid;
	PCWSTR pUsername;
	DWORD tokenId;
	BOOL elevateIt;
	BOOL runIt;
	PCWSTR pCommandLine;
	BOOL isSidDirectUser;

	//KUHL_M_TOKEN_ELEVATE_DATA_TYPE_FILTER filter;
	//BOOL isNeeded;
	//BOOL isMinimal;
} KUHL_M_TOKEN_ELEVATE_DATA, *PKUHL_M_TOKEN_ELEVATE_DATA;

void kuhl_m_token_displayAccount_sids(UCHAR l, DWORD count, PSID_AND_ATTRIBUTES sids);
void kuhl_m_token_displayAccount(HANDLE hToken, BOOL full);

NTSTATUS kuhl_m_token_whoami(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_elevate(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_run(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_token_revert(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_token_list_or_elevate(int argc, wchar_t * argv[], BOOL elevate, BOOL runIt);
BOOL CALLBACK kuhl_m_token_list_or_elevate_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);