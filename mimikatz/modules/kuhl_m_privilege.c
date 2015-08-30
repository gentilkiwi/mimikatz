/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_privilege.h"

const KUHL_M_C kuhl_m_c_privilege[] = {
	{kuhl_m_privilege_debug,		L"debug",		L"Ask debug privilege"},
};

const KUHL_M kuhl_m_privilege = {
	L"privilege", L"Privilege module", NULL,
	ARRAYSIZE(kuhl_m_c_privilege), kuhl_m_c_privilege, NULL, NULL
};

NTSTATUS kuhl_m_privilege_simple(ULONG privId)
{
	ULONG previousState;
	NTSTATUS status;
	status = RtlAdjustPrivilege(privId, TRUE, FALSE, &previousState);
	if(NT_SUCCESS(status))
		kprintf(L"Privilege \'%u\' OK\n", privId);
	else
		PRINT_ERROR(L"RtlAdjustPrivilege (%u) %08x\n", privId, status);
	return status;
}

NTSTATUS kuhl_m_privilege_debug(int argc, wchar_t * argv[])
{
	return kuhl_m_privilege_simple(SE_DEBUG);
}