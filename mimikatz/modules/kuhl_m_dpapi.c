/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_dpapi.h"

const KUHL_M_C kuhl_m_c_dpapi[] = {
	{kuhl_m_dpapi_masterkeys,		L"masterkeys",		L""},
};
const KUHL_M kuhl_m_dpapi = {
	L"dpapi",	L"", NULL,
	ARRAYSIZE(kuhl_m_c_dpapi), kuhl_m_c_dpapi, NULL, NULL
};

NTSTATUS kuhl_m_dpapi_masterkeys(int argc, wchar_t * argv[])
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys;
	PBYTE buffer;
	DWORD szBuffer;

	if(argc && kull_m_file_readData(argv[0], &buffer, &szBuffer))
	{
		if(masterkeys = kull_m_dpapi_masterkeys_create(buffer))
		{
			kull_m_dpapi_masterkeys_descr(masterkeys);
			kull_m_dpapi_masterkeys_delete(masterkeys);
		}
		LocalFree(buffer);
	}
	return STATUS_SUCCESS;
}