/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_net.h"

BOOL kull_m_net_getCurrentDomainInfo(PPOLICY_DNS_DOMAIN_INFO * pDomainInfo)
{
	BOOL status = FALSE;
	LSA_HANDLE hLSA;
	LSA_OBJECT_ATTRIBUTES oaLsa = {0};

	if(NT_SUCCESS(LsaOpenPolicy(NULL, &oaLsa, POLICY_VIEW_LOCAL_INFORMATION, &hLSA)))
	{
		status = NT_SUCCESS(LsaQueryInformationPolicy(hLSA, PolicyDnsDomainInformation, (PVOID *) pDomainInfo));
		LsaClose(hLSA);
	}
	return status;
}

BOOL kull_m_net_CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid, PSID * pSid)
{
	BOOL status = FALSE;
	DWORD szNeeded = 0, dwError;
	CreateWellKnownSid(WellKnownSidType, DomainSid, NULL, &szNeeded);
	dwError = GetLastError();
	if((dwError == ERROR_INVALID_PARAMETER) || (dwError == ERROR_INSUFFICIENT_BUFFER))
		if(*pSid = (PSID) LocalAlloc(LPTR, szNeeded))
			if(!(status = CreateWellKnownSid(WellKnownSidType, DomainSid, *pSid, &szNeeded)))
				*pSid = LocalFree(*pSid);
	return status;
}

BOOL kull_m_net_getDC(LPCWSTR fullDomainName, DWORD altFlags, LPWSTR * fullDCName)
{
	BOOL status = FALSE;
	DWORD ret, size;
	PDOMAIN_CONTROLLER_INFO cInfo = NULL;
	ret = DsGetDcName(NULL, fullDomainName, NULL, NULL, altFlags | DS_IS_DNS_NAME | DS_RETURN_DNS_NAME, &cInfo);
	if(ret == ERROR_SUCCESS)
	{
		size = (DWORD) (wcslen(cInfo->DomainControllerName + 2) + 1) * sizeof(wchar_t);
		if(*fullDCName = (wchar_t *) LocalAlloc(LPTR, size))
		{
			status = TRUE;
			RtlCopyMemory(*fullDCName, cInfo->DomainControllerName + 2, size);
		}
		NetApiBufferFree(cInfo);
	}
	else PRINT_ERROR(L"DsGetDcName: %u\n", ret);
	return status;
}

BOOL kull_m_net_getComputerName(BOOL isFull, LPWSTR *name)
{
	BOOL status = FALSE;
	COMPUTER_NAME_FORMAT ft = isFull ? ComputerNamePhysicalDnsFullyQualified : ComputerNamePhysicalNetBIOS;
	DWORD dwSize = 0;
	if(!GetComputerNameEx(ft, NULL, &dwSize) && (GetLastError() == ERROR_MORE_DATA))
	{
		if(*name = (wchar_t *) LocalAlloc(LPTR, dwSize * sizeof(wchar_t)))
		{
			if(!(status = GetComputerNameEx(ft, *name, &dwSize)))
			{
				PRINT_ERROR_AUTO(L"GetComputerNameEx(data)");
				LocalFree(*name);
			}
		}
	}
	else PRINT_ERROR_AUTO(L"GetComputerNameEx(init)");
	return status;
}