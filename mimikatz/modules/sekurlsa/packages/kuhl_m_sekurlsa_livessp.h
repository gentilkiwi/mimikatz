/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../kuhl_m_sekurlsa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_livessp_package;

NTSTATUS kuhl_m_sekurlsa_livessp(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_livessp(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PLUID logId, IN PVOID pCredentials, IN OPTIONAL PKUHL_M_SEKURLSA_EXTERNAL externalCallback, IN OPTIONAL LPVOID externalCallbackData);

typedef struct _KIWI_LIVESSP_PRIMARY_CREDENTIAL
{
	ULONG isSupp;
	ULONG unk0;
	KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
} KIWI_LIVESSP_PRIMARY_CREDENTIAL, *PKIWI_LIVESSP_PRIMARY_CREDENTIAL;

typedef struct _KIWI_LIVESSP_LIST_ENTRY
{
	struct _KIWI_LIVESSP_LIST_ENTRY *Flink;
	struct _KIWI_LIVESSP_LIST_ENTRY *Blink;
	PVOID	unk0;
	PVOID	unk1;
	PVOID	unk2;
	PVOID	unk3;
	DWORD	unk4;
	DWORD	unk5;
	PVOID	unk6;
	LUID	LocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	PVOID	unk7;
	PKIWI_LIVESSP_PRIMARY_CREDENTIAL suppCreds;
} KIWI_LIVESSP_LIST_ENTRY, *PKIWI_LIVESSP_LIST_ENTRY;
