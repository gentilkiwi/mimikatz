/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_net.h"

BOOL kull_m_net_getCurrentDomainInfo(PPOLICY_DNS_DOMAIN_INFO * pDomainInfo)
{
	BOOL status = FALSE;
	LSA_HANDLE hLSA;
	LSA_OBJECT_ATTRIBUTES oaLsa;

	RtlZeroMemory(&oaLsa, sizeof(LSA_OBJECT_ATTRIBUTES));
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