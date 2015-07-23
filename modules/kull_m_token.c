/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
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
				if((result = kull_m_token_getNameDomainFromSID(pTokenUser->User.Sid, pName, pDomain, pSidNameUse)) && pSid)
					result = ConvertSidToStringSid(pTokenUser->User.Sid, pSid);
			}
			LocalFree(pTokenUser);
		}
	}
	return result;
}

BOOL kull_m_token_getNameDomainFromSID(PSID pSid, PWSTR * pName, PWSTR * pDomain, PSID_NAME_USE pSidNameUse)
{
	BOOL result = FALSE;
	SID_NAME_USE sidNameUse;
	PSID_NAME_USE peUse = pSidNameUse ? pSidNameUse : &sidNameUse;
	DWORD cchName = 0, cchReferencedDomainName = 0;
	
	if(!LookupAccountSid(NULL, pSid, NULL, &cchName, NULL, &cchReferencedDomainName, peUse) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		if(*pName = (PWSTR) LocalAlloc(LPTR, cchName * sizeof(wchar_t)))
		{
			if(*pDomain = (PWSTR) LocalAlloc(LPTR, cchReferencedDomainName * sizeof(wchar_t)))
			{
				result = LookupAccountSid(NULL, pSid, *pName, &cchName, *pDomain, &cchReferencedDomainName, peUse);
				if(!result)
					*pDomain = (PWSTR) LocalFree(*pDomain);
			}
			if(!result)
				*pName = (PWSTR) LocalFree(*pName);
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