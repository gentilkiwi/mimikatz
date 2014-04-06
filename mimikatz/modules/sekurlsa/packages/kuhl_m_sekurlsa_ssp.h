/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../kuhl_m_sekurlsa.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_ssp_package;

NTSTATUS kuhl_m_sekurlsa_ssp(int argc, wchar_t * argv[]);
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_ssp(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PLUID logId, IN PVOID pCredentials, IN OPTIONAL PKUHL_M_SEKURLSA_EXTERNAL externalCallback, IN OPTIONAL LPVOID externalCallbackData);

typedef struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY {
	struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Flink;
	struct _KIWI_SSP_CREDENTIAL_LIST_ENTRY *Blink;
	ULONG References;
	ULONG CredentialReferences;
	LUID LogonId;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
} KIWI_SSP_CREDENTIAL_LIST_ENTRY, *PKIWI_SSP_CREDENTIAL_LIST_ENTRY;