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
	{kuhl_m_net_tod,		L"tod",	L""},
	{kuhl_m_net_stats,		L"stats", L""},
	{kuhl_m_net_share,		L"share", L""},
	{kuhl_m_net_serverinfo,	L"serverinfo", L""},
	{kuhl_m_net_trust,		L"trust", L""},
	{kuhl_m_net_deleg,		L"deleg", L""},
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

NTSTATUS kuhl_m_net_tod(int argc, wchar_t * argv[])
{
	NET_API_STATUS nStatus;
	PTIME_OF_DAY_INFO info = NULL;
	SYSTEMTIME st;
	FILETIME ft;

	nStatus = NetRemoteTOD(argc ? argv[0] : NULL, &info);
	if(nStatus == NERR_Success)
	{
		st.wYear = (WORD) info->tod_year;
		st.wMonth = (WORD) info->tod_month;
		st.wDayOfWeek = (WORD) info->tod_weekday;
		st.wDay = (WORD) info->tod_day;
		st.wHour = (WORD) info->tod_hours;
		st.wMinute = (WORD) info->tod_mins;
		st.wSecond = (WORD) info->tod_secs;
		st.wMilliseconds = (WORD) info->tod_hunds * 10;
		SystemTimeToFileTime(&st, &ft);

		kprintf(L"Remote time (local): ");
		kull_m_string_displayLocalFileTime(&ft);
		kprintf(L"\n");
		//*((PULONGLONG) &ft) -= info->tod_msecs * (ULONGLONG) 10000;
		//kprintf(L"Last startup       : ");
		//kull_m_string_displayLocalFileTime(&ft);
		//kprintf(L"\n");
		NetApiBufferFree(info);
	}
	else PRINT_ERROR(L"NetRemoteTOD: %08x\n", nStatus);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_net_stats(int argc, wchar_t * argv[])
{
	NET_API_STATUS nStatus;
	PSTAT_WORKSTATION_0 pStats = NULL;
	nStatus = NetStatisticsGet(argc ? argv[0] : NULL, SERVICE_WORKSTATION, 0, 0, (LPBYTE *) &pStats);
	if(nStatus == NERR_Success)
	{
		kprintf(SERVICE_WORKSTATION L" StatisticsStartTime: ");
		kull_m_string_displayLocalFileTime((PFILETIME) &pStats->StatisticsStartTime);
		kprintf(L"\n");
		NetApiBufferFree(pStats);
	}
	else PRINT_ERROR(L"NetStatisticsGet: %08x\n", nStatus);
	return STATUS_SUCCESS;
}

void kuhl_m_net_share_type(DWORD type)
{
	switch(type & STYPE_MASK)
	{
	case STYPE_DISKTREE:
		kprintf(L"disktree ; ");
		break;
	case STYPE_PRINTQ:
		kprintf(L"printq ; ");
		break;
	case STYPE_DEVICE:
		kprintf(L"device ; ");
		break;
	case STYPE_IPC:
		kprintf(L"ipc ; ");
		break;
	}

	if(type & STYPE_TEMPORARY)
		kprintf(L"temporary ; ");
	if(type & STYPE_SPECIAL)
		kprintf(L"special ; ");
	if(type & STYPE_RESERVED_ALL)
		kprintf(L"reserved flag(s) ; ");
	kprintf(L"\n");
}

NTSTATUS kuhl_m_net_share(int argc, wchar_t * argv[])
{
	LPSHARE_INFO_502 pBuf;
	DWORD dwEntriesRead;
	DWORD dwTotalEntries;
	DWORD dwResumeHandle = 0;
	DWORD i;
	NET_API_STATUS nStatus;
	do
	{
		nStatus = NetShareEnum (argc ? argv[0] : NULL, 502, (LPBYTE*) &pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
		if((nStatus == 0) || (nStatus == ERROR_MORE_DATA))
		{
			for (i = 0; i < dwEntriesRead; i++)
			{
				kprintf(L"\n"
					L"Netname : %s\n"
					L"Type    : %08x - ",
					pBuf[i].shi502_netname, pBuf[i].shi502_type);
				kuhl_m_net_share_type(pBuf[i].shi502_type);
				kprintf(
					L"Uses    : %u/%u\n"
					L"Path    : %s\n",
					pBuf[i].shi502_current_uses, pBuf[i].shi502_max_uses, pBuf[i].shi502_path);
			}
			NetApiBufferFree(pBuf);
		}
		else PRINT_ERROR(L"NetShareEnum: %08x\n", nStatus);
	}
	while (nStatus == ERROR_MORE_DATA);
	return STATUS_SUCCESS;
}

const wchar_t * SV_TYPES[] = {
	L"workstation", L"server", L"sqlserver", L"domain_ctrl", L"domain_bakctrl", L"time_source", L"afp", L"novelL",
	L"domain_member", L"printq_server", L"dialin_server", L"server_unix", L"nt", L"wfw", L"server_mfpn", L"server_nt",
	L"potential_browser", L"backup_browser", L"master_browser", L"domain_master", L"server_osf", L"server_vms", L"windows", L"dfs", 
	L"cluster_nt", L"terminalserver", L"cluster_vs_nt", L"0x08000000 ?", L"dce", L"alternate_xport", L"local_list_only", L"domain_enum",
};

NTSTATUS kuhl_m_net_serverinfo(int argc, wchar_t * argv[])
{
	LPSERVER_INFO_102 pServerInfo;
	NET_API_STATUS nStatus;
	DWORD i;
	nStatus = NetServerGetInfo(argc ? argv[0] : NULL, 102, (LPBYTE*) &pServerInfo);
	if(nStatus == NERR_Success)
	{
		kprintf(L"platform_id: %u\n"
				L"name       : %s\n"
				L"version    : %u.%u\n"
				L"comment    : %s\n"
				L"type       : %08x - ",
		pServerInfo->sv102_platform_id, pServerInfo->sv102_name, pServerInfo->sv102_version_major, pServerInfo->sv102_version_minor, pServerInfo->sv102_comment, pServerInfo->sv102_type);
		
		for(i = 0; i < ARRAYSIZE(SV_TYPES); i++)
			if((1 << i) & pServerInfo->sv102_type)
				kprintf(L"%s ; ", SV_TYPES[i]);
		kprintf(L"\n");
		NetApiBufferFree(pServerInfo);
	}
	else PRINT_ERROR(L"NetServerGetInfo: %08x\n", nStatus);
	return STATUS_SUCCESS;
}

const PCWCHAR TRUST_ATTRIBUTES_FLAGS[] = {L"IN_FOREST", L"DIRECT_OUTBOUND", L"TREE_ROOT", L"PRIMARY", L"NATIVE_MODE", L"DIRECT_INBOUND"};
const PCWCHAR TRUST_ATTRIBUTES[] = {L"NON_TRANSITIVE", L"UPLEVEL_ONLY", L"FILTER_SIDS/QUARANTINED_DOMAIN", L"FOREST_TRANSITIVE", L"CROSS_ORGANIZATION", L"WITHIN_FOREST", L"TREAT_AS_EXTERNAL", L"TRUST_USES_RC4_ENCRYPTION", L"TRUST_USES_AES_KEYS"};
const PCWCHAR TRUST_ATTRIBUTES_LEGACY[] = {L"TREE_PARENT", L"TREE_ROOT"}; // 0x00400000, 0x00800000
const PCWCHAR TRUST_DIRECTION[] = {L"DISABLED", L"INBOUND", L"OUTBOUND", L"BIDIRECTIONAL"};
NTSTATUS kuhl_m_net_trust(int argc, wchar_t * argv[])
{
	PDS_DOMAIN_TRUSTS pTrusts;
	ULONG uTrusts;
	DWORD ret, i, j;
	PWCHAR server, dn, sysDN, pAttribute, myAttrs[] = {L"trustPartner", L"flatName", L"trustAttributes", L"trustDirection", L"trustType", L"objectGUID", NULL};
	PLDAP ld;
	PLDAPMessage pMessage = NULL, pEntry;
	BerElement* pBer = NULL;
	PBERVAL *pBerVal;
	PCHAR aBuffer;

	kull_m_string_args_byName(argc, argv, L"server", &server, NULL);

	kprintf(L"RPC mode: ");
	ret = DsEnumerateDomainTrusts(server, DS_DOMAIN_VALID_FLAGS, &pTrusts, &uTrusts);
	if(ret == ERROR_SUCCESS)
	{
		for(i = 0; i < uTrusts; i++)
		{
			kprintf(L"\n[%2u] Netbios   : %s\n     DNS       : %s\n     Flags     : 0x%08x ( ", i, pTrusts[i].NetbiosDomainName, pTrusts[i].DnsDomainName, pTrusts[i].Flags);
			for(j = 0; j < (8 * sizeof(DWORD)); j++)
				if((pTrusts[i].Flags >> j) & 1)
					kprintf(L"%s ; ", (j < ARRAYSIZE(TRUST_ATTRIBUTES_FLAGS)) ? TRUST_ATTRIBUTES_FLAGS[j] : L"?");
			kprintf(L")\n");
			if((pTrusts[i].Flags & DS_DOMAIN_IN_FOREST) && !(pTrusts[i].Flags & DS_DOMAIN_TREE_ROOT))
				kprintf(L"     Parent    : [%2u] %s\n", pTrusts[i].ParentIndex, pTrusts[pTrusts[i].ParentIndex].NetbiosDomainName);
			kprintf(L"     Type      : 0x%08x - ", pTrusts[i].TrustType);
			switch(pTrusts[i].TrustType)
			{
			case TRUST_TYPE_DOWNLEVEL:
				kprintf(L"DOWNLEVEL (DC < 2000)\n");
				break;
			case TRUST_TYPE_UPLEVEL:
				kprintf(L"UPLEVEL (DC >= 2000)\n");
				break;
			case TRUST_TYPE_MIT:
				kprintf(L"MIT Kerberos realm\n");
				break;
			case 0x00000004 /*TRUST_TYPE_DCE*/:
				kprintf(L"DCE realm\n");
				break;
			default:
				if((pTrusts[i].TrustType >= 0x5) && (pTrusts[i].TrustType <= 0x000fffff))
					kprintf(L"reserved for future use\n");
				else if((pTrusts[i].TrustType >= 0x00100000) && (pTrusts[i].TrustType <= 0xfff00000))
					kprintf(L"provider specific trust level\n");
				else kprintf(L"?\n");
			}
			kprintf(L"     Attributes: 0x%08x ( ", pTrusts[i].TrustAttributes);
			for(j = 0; j < (8 * sizeof(DWORD) - 10); j++)
				if((pTrusts[i].TrustAttributes >> j) & 1)
					kprintf(L"%s ; ", (j < ARRAYSIZE(TRUST_ATTRIBUTES)) ? TRUST_ATTRIBUTES[j] : L"?");
			for(j = 0; j < 10; j++)
				if((pTrusts[i].TrustAttributes >> (j + 22)) & 1)
					kprintf(L"%s ; ", (j < ARRAYSIZE(TRUST_ATTRIBUTES_LEGACY)) ? TRUST_ATTRIBUTES_LEGACY[j] : L"?");
			kprintf(L")\n     SID       : ");
			kull_m_string_displaySID(pTrusts[i].DomainSid);
			kprintf(L"\n     GUID      : ");
			kull_m_string_displayGUID(&pTrusts[i].DomainGuid);
			kprintf(L"\n");
		}
		NetApiBufferFree(pTrusts);
	}
	else PRINT_ERROR(L"DsEnumerateDomainTrusts: %u\n", ret);

	kprintf(L"\n\nLDAP mode: ");
	if(kull_m_ldap_getLdapAndRootDN(server, L"defaultNamingContext", &ld, &dn))
	{
		if(kull_m_string_sprintf(&sysDN, L"CN=System,%s", dn))
		{
			ret = ldap_search_s(ld, sysDN, LDAP_SCOPE_ONELEVEL, L"(objectClass=trustedDomain)", myAttrs,  FALSE, &pMessage);
			if(ret == LDAP_SUCCESS)
			{
				kprintf(L"%u entries\n", ldap_count_entries(ld, pMessage));
				for(pEntry = ldap_first_entry(ld, pMessage); pEntry; pEntry = ldap_next_entry(ld, pEntry))
				{
					kprintf(L"\n%s\n", ldap_get_dn(ld, pEntry));
					for(pAttribute = ldap_first_attribute(ld, pEntry, &pBer); pAttribute; pAttribute = ldap_next_attribute(ld, pEntry, pBer))
					{
						kprintf(L"  %s: ", pAttribute);
						if(pBerVal = ldap_get_values_len(ld, pEntry, pAttribute))
						{
							if((_wcsicmp(pAttribute, L"objectGUID") == 0))
							{
								kull_m_string_displayGUID((LPGUID) pBerVal[0]->bv_val);
								kprintf(L"\n");
							}
							else if(
								(_wcsicmp(pAttribute, L"trustPartner") == 0) ||
								(_wcsicmp(pAttribute, L"flatName") == 0)
								)
							{
								kprintf(L"%*S\n", pBerVal[0]->bv_len, pBerVal[0]->bv_val);
							}
							else
							{
								if(kull_m_string_copyA_len(&aBuffer, pBerVal[0]->bv_val, pBerVal[0]->bv_len))
								{
									ret = strtoul(aBuffer, NULL, 10);
									kprintf(L"0x%08x - ", ret);


									if(_wcsicmp(pAttribute, L"trustAttributes") == 0)
									{
										for(j = 0; j < (8 * sizeof(DWORD) - 10); j++)
											if((ret >> j) & 1)
												kprintf(L"%s ; ", (j < ARRAYSIZE(TRUST_ATTRIBUTES)) ? TRUST_ATTRIBUTES[j] : L"?");
										for(j = 0; j < 10; j++)
											if((ret >> (j + 22)) & 1)
												kprintf(L"%s ; ", (j < ARRAYSIZE(TRUST_ATTRIBUTES_LEGACY)) ? TRUST_ATTRIBUTES_LEGACY[j] : L"?");
										kprintf(L"\n");
									}
									else if(_wcsicmp(pAttribute, L"trustType") == 0)
									{
										switch(ret)
										{
										case TRUST_TYPE_DOWNLEVEL:
											kprintf(L"DOWNLEVEL (DC < 2000)\n");
											break;
										case TRUST_TYPE_UPLEVEL:
											kprintf(L"UPLEVEL (DC >= 2000)\n");
											break;
										case TRUST_TYPE_MIT:
											kprintf(L"MIT Kerberos realm\n");
											break;
										case 0x00000004 /*TRUST_TYPE_DCE*/:
											kprintf(L"DCE realm\n");
											break;
										default:
											if((pTrusts[i].TrustType >= 0x5) && (pTrusts[i].TrustType <= 0x000fffff))
												kprintf(L"reserved for future use\n");
											else if((pTrusts[i].TrustType >= 0x00100000) && (pTrusts[i].TrustType <= 0xfff00000))
												kprintf(L"provider specific trust level\n");
											else kprintf(L"?\n");
										}
									}
									else if(_wcsicmp(pAttribute, L"trustDirection") == 0)
										kprintf(L"%s\n", TRUST_DIRECTION[ret & 0x00000003]);
									LocalFree(aBuffer);
								}
							}
							ldap_value_free_len(pBerVal);
						}
						ldap_memfree(pAttribute);
					}
					if(pBer)
						ber_free(pBer, 0);
				}
			}
			else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", ret, ret);
			if(pMessage)
				ldap_msgfree(pMessage);
			LocalFree(sysDN);
		}
		LocalFree(dn);
		ldap_unbind(ld);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_net_deleg(int argc, wchar_t * argv[])
{
	DWORD i, dwRet;
	PLDAP ld;
	PWCHAR server, dn, pAttribute, myAttrs[] = {L"userPrincipalName", L"sAMAccountName", L"userAccountControl", L"servicePrincipalName", L"msDS-AllowedToDelegateTo", L"msDS-AllowedToActOnBehalfOfOtherIdentity", L"objectSid", L"objectGUID", NULL},
		filter = L"(&"
L"(servicePrincipalname=*)"
L"(|(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(msDS-AllowedToDelegateTo=*)(UserAccountControl:1.2.840.113556.1.4.804:=17301504))"
L"(!(UserAccountControl:1.2.840.113556.1.4.804:=67117056))"
L"(|(objectcategory=computer)(objectcategory=person)(objectcategory=msDS-GroupManagedServiceAccount)(objectcategory=msDS-ManagedServiceAccount))"
L")";
	PCHAR aBuffer, aQuery;
	PLDAPMessage pMessage = NULL, pEntry;
	BerElement* pBer = NULL;
	PBERVAL *pBerVal;
	
	DNS_STATUS dnsStatus;
	PDNS_RECORD pRecords;

	BOOL isCheckDNS = kull_m_string_args_byName(argc, argv, L"dns", NULL, NULL);
	kull_m_string_args_byName(argc, argv, L"server", &server, NULL);

	if(kull_m_ldap_getLdapAndRootDN(server, NULL, &ld, &dn))
	{
		dwRet = ldap_search_s(ld, dn, LDAP_SCOPE_SUBTREE, filter, myAttrs, FALSE, &pMessage);
		if(dwRet == LDAP_SUCCESS)
		{
			kprintf(L"%u entries\n", ldap_count_entries(ld, pMessage));
			for(pEntry = ldap_first_entry(ld, pMessage); pEntry; pEntry = ldap_next_entry(ld, pEntry))
			{
				kprintf(L"\n%s\n", ldap_get_dn(ld, pEntry));
				for(pAttribute = ldap_first_attribute(ld, pEntry, &pBer); pAttribute; pAttribute = ldap_next_attribute(ld, pEntry, pBer))
				{
					kprintf(L"  %s: ", pAttribute);
					if(pBerVal = ldap_get_values_len(ld, pEntry, pAttribute))
					{
						if((_wcsicmp(pAttribute, L"userAccountControl") == 0))
						{
							if(kull_m_string_copyA_len(&aBuffer, pBerVal[0]->bv_val, pBerVal[0]->bv_len))
							{
								dwRet = strtoul(aBuffer, NULL, 10);
								kprintf(L"0x%08x - ", dwRet);
								for(i = 0; i < min(ARRAYSIZE(KUHL_M_LSADUMP_UF_FLAG), sizeof(DWORD) * 8); i++)
									if((1 << i) & dwRet)
										kprintf(L"%s ; ", KUHL_M_LSADUMP_UF_FLAG[i]);
								kprintf(L"\n");
								LocalFree(aBuffer);
							}
						}
						else if(
							(_wcsicmp(pAttribute, L"userPrincipalName") == 0) ||
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
						else if(
							(_wcsicmp(pAttribute, L"servicePrincipalName") == 0) ||
							(_wcsicmp(pAttribute, L"msDS-AllowedToDelegateTo") == 0) ||
							(_wcsicmp(pAttribute, L"msDS-AllowedToActOnBehalfOfOtherIdentity") == 0)
							)
						{
							for(i = 0; pBerVal[i]; i++)
							{
								kprintf(L"\n    %*S", pBerVal[i]->bv_len, pBerVal[i]->bv_val);
								
								if(isCheckDNS && (_wcsicmp(pAttribute, L"servicePrincipalName") == 0))
								{
									if(kull_m_string_copyA_len(&aBuffer, pBerVal[i]->bv_val, pBerVal[i]->bv_len))
									{
										if(strstr(aBuffer, "HTTP/") == aBuffer)
										{
											aQuery = aBuffer + lstrlenA("HTTP/");
											if(*aQuery && strchr(aQuery, '.'))
											{
												pRecords = NULL;
												dnsStatus = DnsQuery_A(aQuery, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_LOCAL_NAME | DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST | DNS_QUERY_TREAT_AS_FQDN, NULL, &pRecords, NULL);
												if((dnsStatus == ERROR_SUCCESS) && pRecords)
													DnsRecordListFree(pRecords, DnsFreeRecordList);
												else if(dnsStatus == DNS_ERROR_RCODE_NAME_ERROR)
													kprintf(L" ** NAME IS NOT REGISTERED! **");
												else PRINT_ERROR(L"DnsQuery: %08x", dnsStatus);
											}
										}
										LocalFree(aBuffer);
									}
								}
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
		else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwRet, dwRet);

		if(pMessage)
			ldap_msgfree(pMessage);
		LocalFree(dn);
		ldap_unbind(ld);
	}
	return STATUS_SUCCESS;
}