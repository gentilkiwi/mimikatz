/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_kerberos_pac.h"

BOOL kuhl_m_pac_validationInfo_to_PAC(PKERB_VALIDATION_INFO validationInfo, DWORD SignatureType, PPACTYPE * pacType, DWORD * pacLength)
{
	BOOL status = FALSE;
	PVOID pLogonInfo = NULL;
	PPAC_CLIENT_INFO pClientInfo = NULL;
	PAC_SIGNATURE_DATA signature = {SignatureType, {0}};
	DWORD szLogonInfo = 0, szLogonInfoAligned, szClientInfo = 0, szClientInfoAligned, szSignature = FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature), szSignatureAligned, offsetData = sizeof(PACTYPE) + 3 * sizeof(PAC_INFO_BUFFER);
	PKERB_CHECKSUM pCheckSum;

	if(NT_SUCCESS(CDLocateCheckSum(SignatureType, &pCheckSum)))
	{
		szSignature += pCheckSum->Size;
		szSignatureAligned = SIZE_ALIGN(szSignature, 8);

		if(kuhl_m_pac_EncodeValidationInformation(validationInfo, &pLogonInfo, &szLogonInfo))
			szLogonInfoAligned = SIZE_ALIGN(szLogonInfo, 8);
		if(kuhl_m_pac_validationInfo_to_CNAME_TINFO(validationInfo, &pClientInfo, &szClientInfo))
			szClientInfoAligned = SIZE_ALIGN(szClientInfo, 8);

		if(pLogonInfo && pClientInfo)
		{
			*pacLength = offsetData + szLogonInfoAligned + szClientInfoAligned + 2 * szSignatureAligned;
			if(*pacType = (PPACTYPE) LocalAlloc(LPTR, *pacLength))
			{
				(*pacType)->cBuffers = 4;
				(*pacType)->Version = 0;

				(*pacType)->Buffers[0].cbBufferSize = szLogonInfo;
				(*pacType)->Buffers[0].ulType = PACINFO_TYPE_LOGON_INFO;
				(*pacType)->Buffers[0].Offset = offsetData;
				RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[0].Offset, pLogonInfo, (*pacType)->Buffers[0].cbBufferSize);

				(*pacType)->Buffers[1].cbBufferSize = szClientInfo;
				(*pacType)->Buffers[1].ulType = PACINFO_TYPE_CNAME_TINFO;
				(*pacType)->Buffers[1].Offset = (*pacType)->Buffers[0].Offset + szLogonInfoAligned;
				RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[1].Offset, pClientInfo, (*pacType)->Buffers[1].cbBufferSize);

				(*pacType)->Buffers[2].cbBufferSize = szSignature;
				(*pacType)->Buffers[2].ulType = PACINFO_TYPE_CHECKSUM_SRV;
				(*pacType)->Buffers[2].Offset = (*pacType)->Buffers[1].Offset + szClientInfoAligned;
				RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[2].Offset, &signature, FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature));

				(*pacType)->Buffers[3].cbBufferSize = szSignature;
				(*pacType)->Buffers[3].ulType = PACINFO_TYPE_CHECKSUM_KDC;
				(*pacType)->Buffers[3].Offset = (*pacType)->Buffers[2].Offset + szSignatureAligned;
				RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[3].Offset, &signature, FIELD_OFFSET(PAC_SIGNATURE_DATA, Signature));

				status = TRUE;
			}
		}

		if(pLogonInfo)
			LocalFree(pLogonInfo);
		if(pClientInfo)
			LocalFree(pClientInfo);
	}
	return status;
}

NTSTATUS kuhl_m_pac_signature(PPACTYPE pacType, DWORD pacLenght, DWORD SignatureType, LPCVOID key, DWORD keySize)
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
				RtlZeroMemory(pSignatureData->Signature, pCheckSum->Size);
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
					pCheckSum->Sum(Context, pCheckSum->Size, checksumSrv);
					pCheckSum->Finalize(Context, checksumpKdc);
					pCheckSum->Finish(&Context);
				}
			}
		}
	}
	return status;
}

BOOL kuhl_m_pac_validationInfo_to_CNAME_TINFO(PKERB_VALIDATION_INFO validationInfo, PPAC_CLIENT_INFO * pacClientInfo, DWORD * pacClientInfoLength)
{
	BOOL status = FALSE;
	*pacClientInfoLength = sizeof(PAC_CLIENT_INFO) + validationInfo->EffectiveName.Length - sizeof(wchar_t);
	if(*pacClientInfo = (PPAC_CLIENT_INFO) LocalAlloc(LPTR, *pacClientInfoLength))
	{
		(*pacClientInfo)->ClientId = validationInfo->LogonTime;
		(*pacClientInfo)->NameLength = validationInfo->EffectiveName.Length;
		RtlCopyMemory((*pacClientInfo)->Name, validationInfo->EffectiveName.Buffer, (*pacClientInfo)->NameLength);
		status = TRUE;
	}
	return status;
}

#ifdef KERBEROS_TOOLS
NTSTATUS kuhl_m_kerberos_pac_info(int argc, wchar_t * argv[])
{
	PPACTYPE pacType;
	DWORD pacLenght, i, j;
	PKERB_VALIDATION_INFO pValInfo;
	PPAC_SIGNATURE_DATA pSignatureData;
	PPAC_CLIENT_INFO pClientInfo;

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
					if(kuhl_m_pac_DecodeValidationInformation((PBYTE) pacType + pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize, &pValInfo))
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
						kuhl_m_pac_FreeValidationInformation(&pValInfo);
						kprintf(L"\n");
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
					kprintf(L"Client   (%hu, %.*s)\n", pClientInfo->NameLength, pClientInfo->NameLength / sizeof(WCHAR), pClientInfo->Name);
					break;
				default:
					kull_m_string_wprintf_hex(&pacType->Buffers[i], sizeof(PAC_INFO_BUFFER), 1);
					kprintf(L"\n");
					kprintf(L"[%02u] %08x @ offset %016llx (%u)\n", i, pacType->Buffers[i].ulType, pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize);
					kull_m_string_wprintf_hex((PBYTE) pacType + pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize, 1);
					kprintf(L"\n");
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