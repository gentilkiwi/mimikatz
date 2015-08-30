/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_net.h"

const KUHL_M_C kuhl_m_c_net[] = {
	{kuhl_m_net_user,		L"user",		L""},
	{kuhl_m_net_localgroup,	L"localgroup",	L""},
	{kuhl_m_net_group,		L"group",		L""},
	//{kuhl_m_net_autoda,		L"autoda",		L""},
};
const KUHL_M kuhl_m_net = {
	L"net",	L"", NULL,
	ARRAYSIZE(kuhl_m_c_net), kuhl_m_c_net, NULL, NULL
};

NTSTATUS kuhl_m_net_user(int argc, wchar_t * argv[])
{
	NTSTATUS status, enumDomainStatus, enumUserStatus;
	UNICODE_STRING serverName, *groupName;
	SAMPR_HANDLE hServerHandle, hBuiltinHandle = NULL, hDomainHandle, hUserHandle;
	DWORD domainEnumerationContext, domainCountRetourned, userEnumerationContext, userCountRetourned, groupsCountRetourned, i, j, k, *usage, aliasCountRetourned, *alias;
	PSAMPR_RID_ENUMERATION pEnumDomainBuffer, pEnumUsersBuffer;
	PSID domainSid, userSid;
	PGROUP_MEMBERSHIP pGroupMemberShip;
	SID builtin = {1, 1, {0, 0, 0, 0, 0, 5}, {32}};

	RtlInitUnicodeString(&serverName, argc ? argv[0] : L"");
	status = SamConnect(&serverName, &hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
	if(NT_SUCCESS(status))
	{
		status = SamOpenDomain(hServerHandle, DOMAIN_LIST_ACCOUNTS | DOMAIN_LOOKUP, &builtin, &hBuiltinHandle);
		if(!NT_SUCCESS(status))
			PRINT_ERROR(L"SamOpenDomain Builtin (?) %08x\n", status);
		
		domainEnumerationContext = 0;
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
										status = SamOpenUser(hDomainHandle, USER_READ_GROUP_INFORMATION | USER_LIST_GROUPS | USER_READ_ACCOUNT | USER_READ_LOGON |  USER_READ_PREFERENCES | USER_READ_GENERAL, pEnumUsersBuffer[j].RelativeId, &hUserHandle);
										if(NT_SUCCESS(status))
										{
											status = SamGetGroupsForUser(hUserHandle, &pGroupMemberShip, &groupsCountRetourned);
											if(NT_SUCCESS(status))
											{
												for(k = 0; k < groupsCountRetourned; k++)
												{
													kprintf(L"\n | %-5u ", pGroupMemberShip[k].RelativeId);
													status = SamLookupIdsInDomain(hDomainHandle, 1, &pGroupMemberShip[k].RelativeId, &groupName, &usage);
													if(NT_SUCCESS(status))
													{
														kprintf(L"%wZ", groupName);
														SamFreeMemory(groupName);
														SamFreeMemory(usage);
													} else PRINT_ERROR(L"SamLookupIdsInDomain %08x", status);
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
														status = SamLookupIdsInDomain(hDomainHandle, 1, &alias[k], &groupName, &usage);
														if(NT_SUCCESS(status))
														{
															kprintf(L"%wZ", groupName);
															SamFreeMemory(groupName);
															SamFreeMemory(usage);
														} else PRINT_ERROR(L"SamLookupIdsInDomain %08x", status);
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
															status = SamLookupIdsInDomain(hBuiltinHandle, 1, &alias[k], &groupName, &usage);
															if(NT_SUCCESS(status))
															{
																kprintf(L"%wZ", groupName);
																SamFreeMemory(groupName);
																SamFreeMemory(usage);
															} else PRINT_ERROR(L"SamLookupIdsInDomain %08x", status);
														}
														SamFreeMemory(alias);
													} else PRINT_ERROR(L"SamGetAliasMembership %08x", status);
												}
												SamFreeMemory(userSid);
											} else PRINT_ERROR(L"SamRidToSid %08x", status);
											SamCloseHandle(hUserHandle);
										} else PRINT_ERROR(L"SamOpenUser %08x", status);
									}
									SamFreeMemory(pEnumUsersBuffer);
								} else PRINT_ERROR(L"SamEnumerateUsersInDomain %08x", enumUserStatus);
							} while(enumUserStatus == STATUS_MORE_ENTRIES);
							SamCloseHandle(hDomainHandle);
						} else PRINT_ERROR(L"SamOpenDomain %08x", status);
						SamFreeMemory(domainSid);
					} else PRINT_ERROR(L"SamLookupDomainInSamServer %08x", status);
				}
				SamFreeMemory(pEnumDomainBuffer);
			} else PRINT_ERROR(L"SamEnumerateDomainsInSamServer %08x\n", enumDomainStatus);
			kprintf(L"\n");
		} while(enumDomainStatus == STATUS_MORE_ENTRIES);

		if(hBuiltinHandle)
			SamCloseHandle(hBuiltinHandle);

		SamCloseHandle(hServerHandle);
	} else PRINT_ERROR(L"SamConnect %08x\n", status);
	
	return ERROR_SUCCESS;
}

NTSTATUS kuhl_m_net_group(int argc, wchar_t * argv[])
{
	return ERROR_SUCCESS;
}

NTSTATUS kuhl_m_net_localgroup(int argc, wchar_t * argv[])
{
	return ERROR_SUCCESS;
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