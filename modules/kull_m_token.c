/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_token.h"

BOOL kull_m_token_getNameDomainFromToken(HANDLE hToken, PWSTR * pName, PWSTR * pDomain, PWSTR * pSid, PSID_NAME_USE pSidNameUse)
{
	BOOL result = FALSE;
	PTOKEN_USER pTokenUser;
	DWORD szNeeded;

	if(!GetTokenInformation(hToken, TokenUser, NULL, 0, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		if(pTokenUser = (PTOKEN_USER) LocalAlloc(LPTR, szNeeded))
		{
			if(GetTokenInformation(hToken, TokenUser, pTokenUser, szNeeded, &szNeeded))
			{
				if((result = kull_m_token_getNameDomainFromSID(pTokenUser->User.Sid, pName, pDomain, pSidNameUse, NULL)) && pSid)
					result = ConvertSidToStringSid(pTokenUser->User.Sid, pSid);
			}
			LocalFree(pTokenUser);
		}
	}
	return result;
}

BOOL kull_m_token_CheckTokenMembership(__in_opt HANDLE TokenHandle, __in PSID SidToCheck, __out PBOOL IsMember)
{
	BOOL status = FALSE, isDupp = FALSE;
	TOKEN_TYPE type;
	DWORD szNeeded;
	HANDLE effHandle;
	
	if(GetTokenInformation(TokenHandle, TokenType, &type, sizeof(TOKEN_TYPE), &szNeeded))
	{
		if(type == TokenPrimary)
		{
			isDupp = DuplicateTokenEx(TokenHandle, TOKEN_QUERY, NULL, SecurityIdentification, TokenImpersonation, &effHandle);
			if(!isDupp)
				PRINT_ERROR_AUTO(L"DuplicateTokenEx");
		}
		else effHandle = TokenHandle;
		
		if(isDupp || (type != TokenPrimary))
		{
			if(!(status = CheckTokenMembership(effHandle, SidToCheck, IsMember)))
				PRINT_ERROR_AUTO(L"CheckTokenMembership");
			if(isDupp)
				CloseHandle(effHandle);
		}
	}
	else PRINT_ERROR_AUTO(L"GetTokenInformation");
	return status;
}

PCWCHAR SidNameUses[] = {L"User", L"Group", L"Domain", L"Alias", L"WellKnownGroup", L"DeletedAccount", L"Invalid", L"Unknown", L"Computer", L"Label"};
PCWCHAR kull_m_token_getSidNameUse(SID_NAME_USE SidNameUse)
{
	return (SidNameUse > 0 && SidNameUse <= SidTypeLabel) ? SidNameUses[SidNameUse - 1] : L"unk!";
}

BOOL kull_m_token_getNameDomainFromSID(PSID pSid, PWSTR * pName, PWSTR * pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system)
{
	BOOL result = FALSE;
	SID_NAME_USE sidNameUse;
	PSID_NAME_USE peUse = pSidNameUse ? pSidNameUse : &sidNameUse;
	DWORD cchName = 0, cchReferencedDomainName = 0;
	
	if(!LookupAccountSid(system, pSid, NULL, &cchName, NULL, &cchReferencedDomainName, peUse) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		if(*pName = (PWSTR) LocalAlloc(LPTR, cchName * sizeof(wchar_t)))
		{
			if(*pDomain = (PWSTR) LocalAlloc(LPTR, cchReferencedDomainName * sizeof(wchar_t)))
			{
				result = LookupAccountSid(system, pSid, *pName, &cchName, *pDomain, &cchReferencedDomainName, peUse);
				if(!result)
					*pDomain = (PWSTR) LocalFree(*pDomain);
			}
			if(!result)
				*pName = (PWSTR) LocalFree(*pName);
		}
	}
	return result;
}

BOOL kull_m_token_getSidDomainFromName(PCWSTR pName, PSID * pSid, PWSTR * pDomain, PSID_NAME_USE pSidNameUse, LPCWSTR system)
{
	BOOL result = FALSE;
	SID_NAME_USE sidNameUse;
	PSID_NAME_USE peUse = pSidNameUse ? pSidNameUse : &sidNameUse;
	DWORD cbSid = 0, cchReferencedDomainName = 0;
	
	if(!LookupAccountName(system, pName, NULL, &cbSid, NULL, &cchReferencedDomainName, peUse) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		if(*pSid = (PSID) LocalAlloc(LPTR, cbSid * sizeof(wchar_t)))
		{
			if(*pDomain = (PWSTR) LocalAlloc(LPTR, cchReferencedDomainName * sizeof(wchar_t)))
			{
				result = LookupAccountName(system, pName, *pSid, &cbSid, *pDomain, &cchReferencedDomainName, peUse);
				if(!result)
					*pDomain = (PWSTR) LocalFree(*pDomain);
			}
			if(!result)
				*pSid = (PSID) LocalFree(*pSid);
		}
	}
	return result;
}

BOOL kull_m_token_getTokens(PKULL_M_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg)
{
	BOOL status = FALSE;
	KULL_M_TOKEN_ENUM_DATA data = {callBack, pvArg, TRUE};
	if(status = NT_SUCCESS(kull_m_process_getProcessInformation(kull_m_token_getTokens_process_callback, &data)))
		if(data.mustContinue)
			status = NT_SUCCESS(kull_m_handle_getHandlesOfType(kull_m_token_getTokens_handles_callback, L"Token", TOKEN_QUERY | TOKEN_DUPLICATE, 0, &data));
	return status;
}

BOOL kull_m_token_getTokensUnique(PKULL_M_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg)
{
	BOOL status = FALSE, mustContinue = TRUE;
	KULL_M_TOKEN_LIST list = {0}, *cur, *tmp;
	if(status = kull_m_token_getTokens(kull_m_token_getTokensUnique_callback, &list))
	{
		for(cur = &list; cur && mustContinue; cur = cur->next)
			mustContinue = callBack(cur->hToken, cur->ptid, pvArg);

		for(cur = &list; cur; cur = tmp)
		{
			if(cur->hToken)
				CloseHandle(cur->hToken);
			tmp = cur->next;
			if(cur != &list)
				LocalFree(cur);
		}
	}
	return status;
}

BOOL CALLBACK kull_m_token_getTokensUnique_callback(HANDLE hToken, DWORD ptid, PVOID pvArg)
{
	PKULL_M_TOKEN_LIST list = (PKULL_M_TOKEN_LIST) pvArg, cur, old = NULL;
	HANDLE my = GetCurrentProcess();
	if(list->hToken)
	{
		for(cur = list; cur; old = cur, cur = cur->next)
			if(kull_m_token_equal(hToken, cur->hToken))
				break;
		if(!cur && old)
			if(old->next = (PKULL_M_TOKEN_LIST) LocalAlloc(LPTR, sizeof(KULL_M_TOKEN_LIST)))
			{
				old->next->ptid = ptid;
				if(!DuplicateHandle(my, hToken, (HANDLE) my, &old->next->hToken, 0, FALSE, DUPLICATE_SAME_ACCESS))
					PRINT_ERROR_AUTO(L"DuplicateHandle");
			}
	}
	else
	{
		list->ptid = ptid;
		if(!DuplicateHandle(my, hToken, my, &list->hToken, 0, FALSE, DUPLICATE_SAME_ACCESS))
		PRINT_ERROR_AUTO(L"DuplicateHandle");
	}
	return TRUE;
}

BOOL CALLBACK kull_m_token_getTokens_process_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
{
	BOOL status = TRUE;
	HANDLE hProcess, hToken;
	
	if(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PtrToUlong(pSystemProcessInformation->UniqueProcessId)))
	{
		if(OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
		{
			status = ((PKULL_M_TOKEN_ENUM_DATA) pvArg)->callback(hToken, PtrToUlong(pSystemProcessInformation->UniqueProcessId), ((PKULL_M_TOKEN_ENUM_DATA) pvArg)->pvArg);
			CloseHandle(hToken);
		}
		CloseHandle(hProcess);
	}
	return (((PKULL_M_TOKEN_ENUM_DATA) pvArg)->mustContinue = status);
}

BOOL CALLBACK kull_m_token_getTokens_handles_callback(HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg)
{
	return (((PKULL_M_TOKEN_ENUM_DATA) pvArg)->mustContinue = ((PKULL_M_TOKEN_ENUM_DATA) pvArg)->callback(handle, pSystemHandle->ProcessId, ((PKULL_M_TOKEN_ENUM_DATA) pvArg)->pvArg));
}

BOOL kull_m_token_equal(IN HANDLE First, IN HANDLE Second)
{
	BOOL status = FALSE;
	BOOLEAN lit;
	NTSTATUS ntStatus;
	DWORD s1, s2, szRet;
	ntStatus = NtCompareTokens(First, Second, &lit);
	if(NT_SUCCESS(ntStatus))
	{
		if(status = lit)
			if(GetTokenInformation(First, TokenSessionId, &s1, sizeof(DWORD), &szRet) && GetTokenInformation(Second, TokenSessionId, &s2, sizeof(DWORD), &szRet))
				status = (s1 == s2);
	}
	else PRINT_ERROR(L"NtCompareTokens: %08x\n", ntStatus);
	return status;
}

PTOKEN_USER kull_m_token_getUserFromToken(HANDLE hToken)
{
	PTOKEN_USER pTokenUser = NULL;
	DWORD szNeeded;
	if(!GetTokenInformation(hToken, TokenUser, NULL, 0, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		if(pTokenUser = (PTOKEN_USER) LocalAlloc(LPTR, szNeeded))
		{
			if(!GetTokenInformation(hToken, TokenUser, pTokenUser, szNeeded, &szNeeded))
				pTokenUser = (PTOKEN_USER) LocalFree(pTokenUser);
		}
	}
	return pTokenUser;
}

PWSTR kull_m_token_getSidFromToken(HANDLE hToken)
{
	PWSTR Sid = NULL;
	PTOKEN_USER pTokenUser;

	if(pTokenUser = kull_m_token_getUserFromToken(hToken))
	{
		if(!ConvertSidToStringSid(pTokenUser->User.Sid, &Sid))
			Sid = NULL;
		LocalFree(pTokenUser);
	}
	return Sid;
}

PWSTR kull_m_token_getCurrentSid()
{
	PWSTR Sid = NULL;
	HANDLE hToken;
	if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		Sid = kull_m_token_getSidFromToken(hToken);
		CloseHandle(hToken);
	}
	return Sid;
}

const SID SidLocalAccount = {SID_REVISION, 1, SECURITY_NT_AUTHORITY, {113}};
BOOL kull_m_token_isLocalAccount(__in_opt HANDLE TokenHandle, __out PBOOL IsMember)
{
	return CheckTokenMembership(TokenHandle, (PSID) &SidLocalAccount, IsMember);
}