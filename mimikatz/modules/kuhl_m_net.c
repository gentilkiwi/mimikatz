/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_net.h"

const KUHL_M_C kuhl_m_c_net[] = {
	{kuhl_m_net_user,		L"user",		L""},
	{kuhl_m_net_group,		L"group",		L""},
	{kuhl_m_net_alias,		L"alias",		L""},
	//{kuhl_m_net_autoda,		L"autoda",		L""},
	{kuhl_m_net_session,	L"session",		L""},
	{kuhl_m_net_wsession,	L"wsession",	L""},
};
const KUHL_M kuhl_m_net = {
	L"net",	L"", NULL,
	ARRAYSIZE(kuhl_m_c_net), kuhl_m_c_net, NULL, NULL
};

NTSTATUS kuhl_m_net_user(int argc, wchar_t * argv[])
{
	NTSTATUS status, enumDomainStatus, enumUserStatus;
	UNICODE_STRING serverName;
	SAMPR_HANDLE hServerHandle, hBuiltinHandle = NULL, hDomainHandle, hUserHandle;
	DWORD domainEnumerationContext = 0, domainCountRetourned, userEnumerationContext, userCountRetourned, groupsCountRetourned, i, j, k, aliasCountRetourned, *alias;
	PSAMPR_RID_ENUMERATION pEnumDomainBuffer, pEnumUsersBuffer;
	PSID domainSid, userSid;
	PGROUP_MEMBERSHIP pGroupMemberShip;
	SID builtin = {SID_REVISION, 1, SECURITY_NT_AUTHORITY, {SECURITY_BUILTIN_DOMAIN_RID}};

	RtlInitUnicodeString(&serverName, argc ? argv[0] : L"");
	status = SamConnect(&serverName, &hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
	if(NT_SUCCESS(status))
	{
		status = SamOpenDomain(hServerHandle, DOMAIN_LIST_ACCOUNTS | DOMAIN_LOOKUP, &builtin, &hBuiltinHandle);
		if(!NT_SUCCESS(status))
			PRINT_ERROR(L"SamOpenDomain Builtin (?) %08x\n", status);
		
		do
		{
			enumDomainStatus = SamEnumerateDomainsInSamServer(hServerHandle, &domainEnumerationContext, &pEnumDomainBuffer, 1, &domainCountRetourned);
			if(NT_SUCCESS(enumDomainStatus) || enumDomainStatus == STATUS_MORE_ENTRIES)
			{
				for(i = 0; i < domainCountRetourned; i++)
				{
					kprintf(L"\nDomain name : %wZ", &pEnumDomainBuffer[i].Name);
					status = SamLookupDomainInSamServer(hServerHandle, &pEnumDomainBuffer[i].Name, &domainSid);
					if(NT_SUCCESS(status))
					{
						kprintf(L"\nDomain SID  : ");
						kull_m_string_displaySID(domainSid);
						
						status = SamOpenDomain(hServerHandle, DOMAIN_LIST_ACCOUNTS | DOMAIN_LOOKUP, domainSid, &hDomainHandle);
						if(NT_SUCCESS(status))
						{
							userEnumerationContext = 0;
							do
							{
								enumUserStatus = SamEnumerateUsersInDomain(hDomainHandle, &userEnumerationContext, 0/*UF_NORMAL_ACCOUNT*/, &pEnumUsersBuffer, 1, &userCountRetourned);
								if(NT_SUCCESS(enumUserStatus) || enumUserStatus == STATUS_MORE_ENTRIES)
								{
									for(j = 0; j < userCountRetourned; j++)
									{
										kprintf(L"\n %-5u %wZ", pEnumUsersBuffer[j].RelativeId, &pEnumUsersBuffer[j].Name);
										status = SamOpenUser(hDomainHandle, USER_READ_GROUP_INFORMATION | USER_LIST_GROUPS | USER_READ_ACCOUNT | USER_READ_LOGON | USER_READ_PREFERENCES | USER_READ_GENERAL, pEnumUsersBuffer[j].RelativeId, &hUserHandle);
										if(NT_SUCCESS(status))
										{
											status = SamGetGroupsForUser(hUserHandle, &pGroupMemberShip, &groupsCountRetourned);
											if(NT_SUCCESS(status))
											{
												for(k = 0; k < groupsCountRetourned; k++)
												{
													kprintf(L"\n | %-5u ", pGroupMemberShip[k].RelativeId);
													kuhl_m_net_simpleLookup(hDomainHandle, pGroupMemberShip[k].RelativeId);
												}
												SamFreeMemory(pGroupMemberShip);
											} else PRINT_ERROR(L"SamGetGroupsForUser %08x", status);

											status = SamRidToSid(hUserHandle, pEnumUsersBuffer[j].RelativeId, &userSid);
											if(NT_SUCCESS(status))
											{
												status = SamGetAliasMembership(hDomainHandle, 1, &userSid, &aliasCountRetourned, &alias);
												if(NT_SUCCESS(status))
												{
													for(k = 0; k < aliasCountRetourned; k++)
													{
														kprintf(L"\n |`%-5u ", alias[k]);
														kuhl_m_net_simpleLookup(hDomainHandle, alias[k]);
													}
													SamFreeMemory(alias);
												} else PRINT_ERROR(L"SamGetAliasMembership %08x", status);

												if(hBuiltinHandle)
												{
													status = SamGetAliasMembership(hBuiltinHandle, 1, &userSid, &aliasCountRetourned, &alias);
													if(NT_SUCCESS(status))
													{
														for(k = 0; k < aliasCountRetourned; k++)
														{
															kprintf(L"\n |´%-5u ", alias[k]);
															kuhl_m_net_simpleLookup(hBuiltinHandle, alias[k]);
														}
														SamFreeMemory(alias);
													}
													else PRINT_ERROR(L"SamGetAliasMembership %08x", status);
												}
												SamFreeMemory(userSid);
											}
											else PRINT_ERROR(L"SamRidToSid %08x", status);
											SamCloseHandle(hUserHandle);
										}
										else PRINT_ERROR(L"SamOpenUser %08x", status);
									}
									SamFreeMemory(pEnumUsersBuffer);
								}
								else PRINT_ERROR(L"SamEnumerateUsersInDomain %08x", enumUserStatus);
							}
							while(enumUserStatus == STATUS_MORE_ENTRIES);
							SamCloseHandle(hDomainHandle);
						}
						else PRINT_ERROR(L"SamOpenDomain %08x", status);
						SamFreeMemory(domainSid);
					}
					else PRINT_ERROR(L"SamLookupDomainInSamServer %08x", status);
				}
				SamFreeMemory(pEnumDomainBuffer);
			}
			else PRINT_ERROR(L"SamEnumerateDomainsInSamServer %08x\n", enumDomainStatus);
			kprintf(L"\n");
		}
		while(enumDomainStatus == STATUS_MORE_ENTRIES);

		if(hBuiltinHandle)
			SamCloseHandle(hBuiltinHandle);

		SamCloseHandle(hServerHandle);
	}
	else PRINT_ERROR(L"SamConnect %08x\n", status);
	
	return ERROR_SUCCESS;
}

NTSTATUS kuhl_m_net_group(int argc, wchar_t * argv[])
{
	NTSTATUS status, enumDomainStatus, enumGroupStatus;
	UNICODE_STRING serverName;
	SAMPR_HANDLE hServerHandle, hDomainHandle, hGroupHandle;
	DWORD domainEnumerationContext = 0, domainCountRetourned, groupEnumerationContext, groupCountRetourned, *members, *attributes, memberRetourned, i, j, k;
	PSAMPR_RID_ENUMERATION pEnumDomainBuffer, pEnumGroupsBuffer;
	PSID domainSid;

	RtlInitUnicodeString(&serverName, argc ? argv[0] : L"");
	status = SamConnect(&serverName, &hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
	if(NT_SUCCESS(status))
	{
		do
		{
			enumDomainStatus = SamEnumerateDomainsInSamServer(hServerHandle, &domainEnumerationContext, &pEnumDomainBuffer, 1, &domainCountRetourned);
			if(NT_SUCCESS(enumDomainStatus) || enumDomainStatus == STATUS_MORE_ENTRIES)
			{
				for(i = 0; i < domainCountRetourned; i++)
				{
					kprintf(L"\nDomain name : %wZ", &pEnumDomainBuffer[i].Name);
					status = SamLookupDomainInSamServer(hServerHandle, &pEnumDomainBuffer[i].Name, &domainSid);
					if(NT_SUCCESS(status))
					{
						kprintf(L"\nDomain SID  : ");
						kull_m_string_displaySID(domainSid);
						
						status = SamOpenDomain(hServerHandle, DOMAIN_LIST_ACCOUNTS | DOMAIN_LOOKUP, domainSid, &hDomainHandle);
						if(NT_SUCCESS(status))
						{
							groupEnumerationContext = 0;
							do
							{
								enumGroupStatus = SamEnumerateGroupsInDomain(hDomainHandle, &groupEnumerationContext, &pEnumGroupsBuffer, 1, &groupCountRetourned);
								if(NT_SUCCESS(enumGroupStatus) || enumGroupStatus == STATUS_MORE_ENTRIES)
								{
									for(j = 0; j < groupCountRetourned; j++)
									{
										kprintf(L"\n %-5u %wZ", pEnumGroupsBuffer[j].RelativeId, &pEnumGroupsBuffer[j].Name);

										status = SamOpenGroup(hDomainHandle, GROUP_LIST_MEMBERS, pEnumGroupsBuffer[j].RelativeId, &hGroupHandle);
										if(NT_SUCCESS(status))
										{
											status = SamGetMembersInGroup(hGroupHandle, &members, &attributes, &memberRetourned);
											if(NT_SUCCESS(status))
											{
												for(k = 0; k < memberRetourned; k++)
												{
													kprintf(L"\n | %-5u ", members[k]);
													kuhl_m_net_simpleLookup(hDomainHandle, members[k]);
												}
												SamFreeMemory(members);
												SamFreeMemory(attributes);
											}
											else PRINT_ERROR(L"SamGetMembersInAlias %08x", status);
											SamCloseHandle(hGroupHandle);
										}
										else PRINT_ERROR(L"SamOpenGroup %08x", status);
									}
									SamFreeMemory(pEnumGroupsBuffer);
								}
								else PRINT_ERROR(L"SamEnumerateGroupsInDomain %08x", enumGroupStatus);
							}
							while(enumGroupStatus == STATUS_MORE_ENTRIES);
							SamCloseHandle(hDomainHandle);
						}
						else PRINT_ERROR(L"SamOpenDomain %08x", status);
						SamFreeMemory(domainSid);
					}
					else PRINT_ERROR(L"SamLookupDomainInSamServer %08x", status);
				}
				SamFreeMemory(pEnumDomainBuffer);
			}
			else PRINT_ERROR(L"SamEnumerateDomainsInSamServer %08x\n", enumDomainStatus);
			kprintf(L"\n");
		}
		while(enumDomainStatus == STATUS_MORE_ENTRIES);
		SamCloseHandle(hServerHandle);
	}
	else PRINT_ERROR(L"SamConnect %08x\n", status);
	
	return ERROR_SUCCESS;
}

NTSTATUS kuhl_m_net_alias(int argc, wchar_t * argv[])
{
	NTSTATUS status, enumDomainStatus, enumAliasStatus;
	UNICODE_STRING serverName;
	SAMPR_HANDLE hServerHandle, hDomainHandle, hAliasHandle;
	DWORD domainEnumerationContext = 0, domainCountRetourned, aliasEnumerationContext, aliasesCountRetourned, memberRetourned, i, j, k;
	PSAMPR_RID_ENUMERATION pEnumDomainBuffer, pEnumAliasBuffer;
	PSID domainSid, *membersSid;

	RtlInitUnicodeString(&serverName, argc ? argv[0] : L"");
	status = SamConnect(&serverName, &hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
	if(NT_SUCCESS(status))
	{
		do
		{
			enumDomainStatus = SamEnumerateDomainsInSamServer(hServerHandle, &domainEnumerationContext, &pEnumDomainBuffer, 1, &domainCountRetourned);
			if(NT_SUCCESS(enumDomainStatus) || enumDomainStatus == STATUS_MORE_ENTRIES)
			{
				for(i = 0; i < domainCountRetourned; i++)
				{
					kprintf(L"\nDomain name : %wZ", &pEnumDomainBuffer[i].Name);
					status = SamLookupDomainInSamServer(hServerHandle, &pEnumDomainBuffer[i].Name, &domainSid);
					if(NT_SUCCESS(status))
					{
						kprintf(L"\nDomain SID  : ");
						kull_m_string_displaySID(domainSid);
						
						status = SamOpenDomain(hServerHandle, DOMAIN_LIST_ACCOUNTS | DOMAIN_LOOKUP, domainSid, &hDomainHandle);
						if(NT_SUCCESS(status))
						{
							aliasEnumerationContext = 0;
							do
							{
								enumAliasStatus = SamEnumerateAliasesInDomain(hDomainHandle, &aliasEnumerationContext, &pEnumAliasBuffer, 1, &aliasesCountRetourned);
								if(NT_SUCCESS(enumAliasStatus) || enumAliasStatus == STATUS_MORE_ENTRIES)
								{
									for(j = 0; j < aliasesCountRetourned; j++)
									{
										kprintf(L"\n %-5u %wZ", pEnumAliasBuffer[j].RelativeId, &pEnumAliasBuffer[j].Name);
										status = SamOpenAlias(hDomainHandle, ALIAS_LIST_MEMBERS, pEnumAliasBuffer[j].RelativeId, &hAliasHandle);
										if(NT_SUCCESS(status))
										{
											status = SamGetMembersInAlias(hAliasHandle, &membersSid, &memberRetourned);
											if(NT_SUCCESS(status))
											{
												for(k = 0; k < memberRetourned; k++)
												{
													kprintf(L"\n | ");
													kull_m_string_displaySID(membersSid[k]);
												}
												SamFreeMemory(membersSid);
											}
											else PRINT_ERROR(L"SamGetMembersInAlias %08x", status);
											SamCloseHandle(hAliasHandle);
										}
										else PRINT_ERROR(L"SamOpenAlias %08x", status);
									}
									SamFreeMemory(pEnumAliasBuffer);
								}
								else PRINT_ERROR(L"SamEnumerateAliasesInDomain %08x", enumAliasStatus);
							}
							while(enumAliasStatus == STATUS_MORE_ENTRIES);
							SamCloseHandle(hDomainHandle);
						}
						else PRINT_ERROR(L"SamOpenDomain %08x", status);
						SamFreeMemory(domainSid);
					}
					else PRINT_ERROR(L"SamLookupDomainInSamServer %08x", status);
				}
				SamFreeMemory(pEnumDomainBuffer);
			}
			else PRINT_ERROR(L"SamEnumerateDomainsInSamServer %08x\n", enumDomainStatus);
			kprintf(L"\n");
		}
		while(enumDomainStatus == STATUS_MORE_ENTRIES);
		SamCloseHandle(hServerHandle);
	}
	else PRINT_ERROR(L"SamConnect %08x\n", status);
	
	return ERROR_SUCCESS;
}

void kuhl_m_net_simpleLookup(SAMPR_HANDLE hDomainHandle, DWORD rid)
{
	NTSTATUS status;
	UNICODE_STRING *name;
	DWORD *usage;

	status = SamLookupIdsInDomain(hDomainHandle, 1, &rid, &name, &usage);
	if(NT_SUCCESS(status))
	{
		kprintf(L"%wZ\t(%s)", name, kull_m_token_getSidNameUse((SID_NAME_USE) *usage));
		SamFreeMemory(name);
		SamFreeMemory(usage);
	}
	else PRINT_ERROR(L"SamLookupIdsInDomain %08x", status);
}
/*
NTSTATUS kuhl_m_net_autoda(int argc, wchar_t * argv[])
{
	PDOMAIN_CONTROLLER_INFO pDCInfos;
	USER_INFO_1 userInfo = {L"", L"", 0, USER_PRIV_USER, NULL, NULL, UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT, NULL,};
	PPOLICY_DNS_DOMAIN_INFO pDomainInfo;
	PSID pSid;
	PWSTR name, domain;
	DWORD parm_err;
	
	if(kull_m_net_getCurrentDomainInfo(&pDomainInfo))
	{
		kprintf(L"Domain   : %wZ/%wZ\n", &pDomainInfo->DnsDomainName, &pDomainInfo->Name);
		if(kull_m_net_CreateWellKnownSid(WinAccountDomainAdminsSid, pDomainInfo->Sid, &pSid))
		{
			if(kull_m_token_getNameDomainFromSID(pSid, &name, &domain, NULL))
			{
				LocalFree(domain);
				kprintf(L"DA group : %s\n", name);
				
				if(DsGetDcName(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_PREFERRED | DS_WRITABLE_REQUIRED, &pDCInfos) == ERROR_SUCCESS)
				{
					domain = pDCInfos->DomainControllerName + 2;
					kprintf(L"DC       : %s\n", domain);
					if(NetUserAdd(domain, 1, (LPBYTE) &userInfo, &parm_err) == NERR_Success)
					{
						W00T(L"User !\n");
						if(NetGroupAddUser(domain, name, userInfo.usri1_name) == NERR_Success)
							W00T(L"Group !\n");
					}
					NetApiBufferFree(pDCInfos);
				}
				LocalFree(name);
				
			} else PRINT_ERROR_AUTO(L"kull_m_token_getNameDomainFromSID");
			LocalFree(pSid);
		}
		else PRINT_ERROR_AUTO(L"kull_m_local_domain_user_CreateWellKnownSid");

		LsaFreeMemory(pDomainInfo);
	}
	return STATUS_SUCCESS;
}
*/

NTSTATUS kuhl_m_net_session(int argc, wchar_t * argv[])
{
	LPSESSION_INFO_10 pBuf;
	DWORD dwEntriesRead;
	DWORD dwTotalEntries;
	DWORD dwResumeHandle = 0;
	DWORD i;
	NET_API_STATUS nStatus;
	do
	{
		nStatus = NetSessionEnum(argc ? argv[0] : NULL, NULL, NULL, 10, (LPBYTE*) &pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
		if((nStatus == 0) || (nStatus == ERROR_MORE_DATA))
		{
			for (i = 0; i < dwEntriesRead; i++)
				kprintf(L"\n"
					L"Client  : %s\n"
					L"Username: %s\n"
					L"Active  : %u\n"
					L"Idle    : %u\n",
					pBuf[i].sesi10_cname, pBuf[i].sesi10_username, pBuf[i].sesi10_time, pBuf[i].sesi10_idle_time);
			NetApiBufferFree(pBuf);
		}
		else PRINT_ERROR(L"NetSessionEnum: %08x\n", nStatus);
	}
	while (nStatus == ERROR_MORE_DATA);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_net_wsession(int argc, wchar_t * argv[])
{
	LPWKSTA_USER_INFO_1 pBuf;
	DWORD dwEntriesRead;
	DWORD dwTotalEntries;
	DWORD dwResumeHandle = 0;
	DWORD i;
	NET_API_STATUS nStatus;
	do
	{
		nStatus = NetWkstaUserEnum (argc ? argv[0] : NULL, 1, (LPBYTE*) &pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
		if((nStatus == 0) || (nStatus == ERROR_MORE_DATA))
		{
			for (i = 0; i < dwEntriesRead; i++)
			{
				kprintf(L"\n"
					L"Username   : %s\n"
					L"Domain     : %s\n"
					L"LogonServer: %s\n",
					pBuf[i].wkui1_username, pBuf[i].wkui1_logon_domain, pBuf[i].wkui1_logon_server);
				if(pBuf[i].wkui1_oth_domains && wcslen(pBuf[i].wkui1_oth_domains))
					kprintf(L"OthDomains : %s\n", pBuf[i].wkui1_oth_domains);
			}
			NetApiBufferFree(pBuf);
		}
		else PRINT_ERROR(L"NetWkstaUserEnum: %08x\n", nStatus);
	}
	while (nStatus == ERROR_MORE_DATA);
	return STATUS_SUCCESS;
}