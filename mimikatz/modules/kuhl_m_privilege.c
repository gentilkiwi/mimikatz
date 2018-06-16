/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_privilege.h"

const KUHL_M_C kuhl_m_c_privilege[] = {
	{kuhl_m_privilege_debug,		L"debug",		L"Ask debug privilege"},
	{kuhl_m_privilege_driver,		L"driver",		L"Ask load driver privilege"},
	{kuhl_m_privilege_security,		L"security",	L"Ask security privilege"},
	{kuhl_m_privilege_tcb,			L"tcb",			L"Ask tcb privilege"},
	{kuhl_m_privilege_backup,		L"backup",		L"Ask backup privilege"},
	{kuhl_m_privilege_restore,		L"restore",		L"Ask restore privilege"},
	{kuhl_m_privilege_sysenv,		L"sysenv",		L"Ask system environment privilege"},

	{kuhl_m_privilege_id,			L"id",			L"Ask a privilege by its id"},
	{kuhl_m_privilege_name,			L"name",		L"Ask a privilege by its name"},
};

const KUHL_M kuhl_m_privilege = {
	L"privilege", L"Privilege module", NULL,
	ARRAYSIZE(kuhl_m_c_privilege), kuhl_m_c_privilege, NULL, NULL
};

NTSTATUS kuhl_m_privilege_simple(ULONG privId)
{
	ULONG previousState;
	NTSTATUS status = RtlAdjustPrivilege(privId, TRUE, FALSE, &previousState);
	if(NT_SUCCESS(status))
		kprintf(L"Privilege \'%u\' OK\n", privId);
	else PRINT_ERROR(L"RtlAdjustPrivilege (%u) %08x\n", privId, status);
	return status;
}

NTSTATUS kuhl_m_privilege_id(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	if(argc)
		status = kuhl_m_privilege_simple(wcstoul(argv[0], NULL, 0));
	else PRINT_ERROR(L"Missing \'id\'\n");
	return status;
}

NTSTATUS kuhl_m_privilege_name(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	LUID luid;
	if(argc)
	{
		if(LookupPrivilegeValue(NULL, argv[0], &luid))
		{
			if(!luid.HighPart)
				status = kuhl_m_privilege_simple(luid.LowPart);
			else PRINT_ERROR(L"LUID high part is %u\n", luid.HighPart);
		}
		else PRINT_ERROR_AUTO(L"LookupPrivilegeValue");
	}
	else PRINT_ERROR(L"Missing \'name\'\n");
	return status;
}

NTSTATUS kuhl_m_privilege_debug(int argc, wchar_t * argv[])
{
	return kuhl_m_privilege_simple(SE_DEBUG);
}

NTSTATUS kuhl_m_privilege_driver(int argc, wchar_t * argv[])
{
	return kuhl_m_privilege_simple(SE_LOAD_DRIVER);
}

NTSTATUS kuhl_m_privilege_security(int argc, wchar_t * argv[])
{
	return kuhl_m_privilege_simple(SE_SECURITY);
}

NTSTATUS kuhl_m_privilege_tcb(int argc, wchar_t * argv[])
{
	return kuhl_m_privilege_simple(SE_TCB);
}
NTSTATUS kuhl_m_privilege_backup(int argc, wchar_t * argv[])
{
	return kuhl_m_privilege_simple(SE_BACKUP);
}

NTSTATUS kuhl_m_privilege_restore(int argc, wchar_t * argv[])
{
	return kuhl_m_privilege_simple(SE_RESTORE);
}

NTSTATUS kuhl_m_privilege_sysenv(int argc, wchar_t * argv[])
{
	return kuhl_m_privilege_simple(SE_SYSTEM_ENVIRONMENT);
}