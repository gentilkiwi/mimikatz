/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_misc_djoin.h"

void kuhl_m_misc_djoin(int argc, wchar_t* argv[])
{
	LPCWSTR szInput;
	PBYTE pbData, pbDecodedData;
	DWORD cbData, cbDecodedData;
	
	if (GET_CLI_ARG(L"input", &szInput))
	{
		kprintf(L"Input   : %s\nOpening : ", szInput);
		if (kull_m_file_readData(szInput, &pbData, &cbData))
		{
			kprintf(L"OK\nDecoding: ");
			if (kull_m_crypto_Base64StringToBinary((LPCWSTR)pbData, &pbDecodedData, &cbDecodedData))
			{
				kprintf(L"OK\n\n");
				kuhl_m_misc_djoin_ODJ_PROVISION_DATA_descr(0, cbDecodedData, pbDecodedData);
				LocalFree(pbDecodedData);
			}
			LocalFree(pbData);
		}
	}
	else PRINT_ERROR(L"An /input:file is needed\n");
}

void kuhl_m_misc_djoin_ODJ_PROVISION_DATA_descr(DWORD level, ULONG cbBlob, PBYTE pBlob)
{
	PODJ_PROVISION_DATA pOdjProvisionData = NULL;
	DWORD i;

	kprintf_level(L"[ODJ_PROVISION_DATA]");
	if (cbBlob && pBlob)
	{
		kprintf(L"\n");
		if (kull_m_rpc_DecodeODJ_PROVISION_DATA(pBlob, cbBlob, &pOdjProvisionData))
		{
			level++;
			kprintf_level(L"ulVersion: %u\n", pOdjProvisionData->ulVersion);
			kprintf_level(L"ulcBlobs : %u\n", pOdjProvisionData->ulcBlobs);

			for (i = 0; i < pOdjProvisionData->ulcBlobs; i++)
			{
				kprintf_level(L"[%u] Blob - ulODJFormat: %u (", i, pOdjProvisionData->pBlobs[i].ulODJFormat);
				switch (pOdjProvisionData->pBlobs[i].ulODJFormat)
				{
				case ODJ_WIN7_FORMAT:
					kprintf(L"windows 7)\n");
					kuhl_m_misc_djoin_ODJ_WIN7BLOB_descr(level + 1, pOdjProvisionData->pBlobs[i].cbBlob, pOdjProvisionData->pBlobs[i].pBlob);
					break;
					
				case ODJ_WIN8_FORMAT:
					kprintf(L"windows 8)\n");
					kuhl_m_misc_djoin_OP_PACKAGE_descr(level + 1, pOdjProvisionData->pBlobs[i].cbBlob, pOdjProvisionData->pBlobs[i].pBlob);
					break;
				default:
					kprintf(L"?)\n");
					kprinthex16(pOdjProvisionData->pBlobs[i].pBlob, pOdjProvisionData->pBlobs[i].cbBlob);
				}
			}

			kull_m_rpc_FreeODJ_PROVISION_DATA(&pOdjProvisionData);
		}
	}
	else kprintf(L" <empty>\n");
}

void kuhl_m_misc_djoin_ODJ_WIN7BLOB_descr(DWORD level, ULONG cbBlob, PBYTE pBlob)
{
	PODJ_WIN7BLOB pOdjWin7Blob = NULL;

	kprintf_level(L"[ODJ_WIN7BLOB]");
	if (cbBlob && pBlob)
	{
		kprintf(L"\n");
		if (kull_m_rpc_DecodeODJ_WIN7BLOB(pBlob, cbBlob, &pOdjWin7Blob))
		{
			level++;
			kprintf_level(L"lpDomain         : %s\n", pOdjWin7Blob->lpDomain);
			kprintf_level(L"lpMachineName    : %s\n", pOdjWin7Blob->lpMachineName);
			kprintf_level(L"lpMachinePassword: %s\n", pOdjWin7Blob->lpMachinePassword);
			kprintf_level(L"DnsDomainInfo\n");
			kprintf_level(L"  Name         : %wZ\n", &pOdjWin7Blob->DnsDomainInfo.Name);
			kprintf_level(L"  DnsDomainName: %wZ\n", &pOdjWin7Blob->DnsDomainInfo.DnsDomainName);
			kprintf_level(L"  DnsForestName: %wZ\n", &pOdjWin7Blob->DnsDomainInfo.DnsForestName);
			kprintf_level(L"  DomainGuid   : ");
			kull_m_cli_guid(&pOdjWin7Blob->DnsDomainInfo.DomainGuid, TRUE);
			kprintf_level(L"  Sid          : ");
			kull_m_cli_sid(pOdjWin7Blob->DnsDomainInfo.Sid, TRUE);
			kprintf_level(L"DcInfo\n");
			kprintf_level(L"  DomainControllerName   : %s\n", pOdjWin7Blob->DcInfo.DomainControllerName);
			kprintf_level(L"  DomainControllerAddress: %s (DomainControllerAddressType: %u)\n", pOdjWin7Blob->DcInfo.DomainControllerAddress, pOdjWin7Blob->DcInfo.DomainControllerAddressType);
			kprintf_level(L"  DomainGuid             : ");
			kull_m_cli_guid(&pOdjWin7Blob->DcInfo.DomainGuid, TRUE);
			kprintf_level(L"  DomainName             : %s\n", pOdjWin7Blob->DcInfo.DomainName);
			kprintf_level(L"  ForestName             : %s\n", pOdjWin7Blob->DcInfo.DnsForestName);
			kprintf_level(L"  Flags                  : 0x%08x\n", pOdjWin7Blob->DcInfo.Flags);
			kprintf_level(L"  DcSiteName             : %s\n", pOdjWin7Blob->DcInfo.DcSiteName);
			kprintf_level(L"  ClientSiteName         : %s\n", pOdjWin7Blob->DcInfo.ClientSiteName);
			kprintf_level(L"Options          : 0x%08x\n", pOdjWin7Blob->Options);

			kull_m_rpc_FreeODJ_WIN7BLOB(&pOdjWin7Blob);
		}
	}
	else kprintf(L" <empty>\n");
}

void kuhl_m_misc_djoin_OP_PACKAGE_descr(DWORD level, ULONG cbBlob, PBYTE pBlob)
{
	POP_PACKAGE pOpPackage = NULL;

	kprintf_level(L"[OP_PACKAGE]");
	if (cbBlob && pBlob)
	{
		kprintf(L"\n");
		if (kull_m_rpc_DecodeOP_PACKAGE(pBlob, cbBlob, &pOpPackage))
		{
			level++;
			kprintf_level(L"EncryptionType           : ");
			kull_m_cli_guid(&pOpPackage->EncryptionType, TRUE);
			kprintf_level(L"EncryptionContext        : 0x%p (%u)\n", pOpPackage->EncryptionContext.pBlob, pOpPackage->EncryptionContext.cbBlob);
			kprintf_level(L"WrappedPartCollection    :\n");
			kuhl_m_misc_djoin_OP_PACKAGE_PART_COLLECTION_descr(level + 1, pOpPackage->WrappedPartCollection.cbBlob, pOpPackage->WrappedPartCollection.pBlob);
			kprintf_level(L"cbDecryptedPartCollection: %u\n", pOpPackage->cbDecryptedPartCollection);
			kprintf_level(L"Extension                : 0x%p (%u)\n", pOpPackage->Extension.pBlob, pOpPackage->Extension.cbBlob);

			kull_m_rpc_FreeOP_PACKAGE(&pOpPackage);
		}
	}
	else kprintf(L" <empty>\n");
}

void kuhl_m_misc_djoin_OP_PACKAGE_PART_COLLECTION_descr(DWORD level, ULONG cbBlob, PBYTE pBlob)
{
	POP_PACKAGE_PART_COLLECTION pOpPackagePartCollection = NULL;
	DWORD i;

	kprintf_level(L"[OP_PACKAGE_PART_COLLECTION]");
	if (cbBlob && pBlob)
	{
		kprintf(L"\n");
		if (kull_m_rpc_DecodeOP_PACKAGE_PART_COLLECTION(pBlob, cbBlob, &pOpPackagePartCollection))
		{
			level++;
			kprintf_level(L"cParts   : %u\n", pOpPackagePartCollection->cParts);
			for (i = 0; i < pOpPackagePartCollection->cParts; i++)
			{
				kprintf_level(L"[%u] Blob\n", i);
				kuhl_m_misc_djoin_OP_PACKAGE_PART_descr(level + 1, pOpPackagePartCollection->pParts + i);
			}
			kprintf_level(L"Extension: 0x%p (%u)\n", pOpPackagePartCollection->Extension.pBlob, pOpPackagePartCollection->Extension.cbBlob);

			kull_m_rpc_FreeOP_PACKAGE_PART_COLLECTION(&pOpPackagePartCollection);
		}
	}
	else kprintf(L" <empty>\n");
}

void kuhl_m_misc_djoin_OP_PACKAGE_PART_descr(DWORD level, POP_PACKAGE_PART pOpPackagePart)
{
	kprintf_level(L"[OP_PACKAGE_PART]\n");
	level++;
	kprintf_level(L"PartType : ");
	kull_m_cli_guid(&pOpPackagePart->PartType, FALSE);

	if (RtlEqualGuid(&pOpPackagePart->PartType, &GUID_JOIN_PROVIDER))
	{
		kprintf(L" - JOIN_PROVIDER\n");
		kuhl_m_misc_djoin_ODJ_WIN7BLOB_descr(level + 1, pOpPackagePart->Part.cbBlob, pOpPackagePart->Part.pBlob);
	}
	else if (RtlEqualGuid(&pOpPackagePart->PartType, &GUID_JOIN_PROVIDER2))
	{
		kprintf(L" - JOIN_PROVIDER2\n");
		kuhl_m_misc_djoin_OP_JOINPROV2_PART_descr(level + 1, pOpPackagePart->Part.cbBlob, pOpPackagePart->Part.pBlob);
	}
	else if (RtlEqualGuid(&pOpPackagePart->PartType, &GUID_JOIN_PROVIDER3))
	{
		kprintf(L" - JOIN_PROVIDER3\n");
		kuhl_m_misc_djoin_OP_JOINPROV3_PART_descr(level + 1, pOpPackagePart->Part.cbBlob, pOpPackagePart->Part.pBlob);
	}
	else if (RtlEqualGuid(&pOpPackagePart->PartType, &GUID_CERT_PROVIDER))
	{
		kprintf(L" - CERT_PROVIDER\n");
		kuhl_m_misc_djoin_OP_CERT_PART_descr(level + 1, pOpPackagePart->Part.cbBlob, pOpPackagePart->Part.pBlob);
	}
	else if (RtlEqualGuid(&pOpPackagePart->PartType, &GUID_POLICY_PROVIDER))
	{
		kprintf(L" - POLICY_PROVIDER\n");
		kuhl_m_misc_djoin_OP_POLICY_PART_descr(level + 1, pOpPackagePart->Part.cbBlob, pOpPackagePart->Part.pBlob);
	}
	else
	{
		kprintf(L" - ?\n");
		kprinthex16(pOpPackagePart->Part.pBlob, pOpPackagePart->Part.cbBlob);
	}

	kprintf_level(L"ulFlags  : 0x%08x\n", pOpPackagePart->ulFlags);
	kprintf_level(L"Extension: 0x%p (%u)\n", pOpPackagePart->Extension.pBlob, pOpPackagePart->Extension.cbBlob);
}

void kuhl_m_misc_djoin_OP_JOINPROV2_PART_descr(DWORD level, ULONG cbBlob, PBYTE pBlob)
{
	POP_JOINPROV2_PART pOpJoinProv2Part = NULL;

	kprintf_level(L"[OP_JOINPROV2_PART]");
	if (cbBlob && pBlob)
	{
		kprintf(L"\n");
		if (kull_m_rpc_DecodeOP_JOINPROV2_PART(pBlob, cbBlob, &pOpJoinProv2Part))
		{
			level++;
			kprintf_level(L"dwFlags           : 0x%08x\n", pOpJoinProv2Part->dwFlags);
			kprintf_level(L"lpNetbiosName     : %s\n", pOpJoinProv2Part->lpNetbiosName);
			kprintf_level(L"lpSiteName        : %s\n", pOpJoinProv2Part->lpSiteName);
			kprintf_level(L"lpPrimaryDNSDomain: %s\n", pOpJoinProv2Part->lpPrimaryDNSDomain);
			kprintf_level(L"dwReserved        : 0x%08x\n", pOpJoinProv2Part->dwReserved);
			kprintf_level(L"lpReserved        : %s\n", pOpJoinProv2Part->lpReserved);

			kull_m_rpc_FreeOP_JOINPROV2_PART(&pOpJoinProv2Part);
		}
	}
	else kprintf(L" <empty>\n");
}

void kuhl_m_misc_djoin_OP_JOINPROV3_PART_descr(DWORD level, ULONG cbBlob, PBYTE pBlob)
{
	POP_JOINPROV3_PART pOpJoinProv3Part = NULL;

	kprintf_level(L"[OP_JOINPROV3_PART]");
	if (cbBlob && pBlob)
	{
		kprintf(L"\n");
		if (kull_m_rpc_DecodeOP_JOINPROV3_PART(pBlob, cbBlob, &pOpJoinProv3Part))
		{
			level++;
			kprintf_level(L"Rid  : %u\n", pOpJoinProv3Part->Rid);
			kprintf_level(L"lpSid: %s\n", pOpJoinProv3Part->lpSid);

			kull_m_rpc_FreeOP_JOINPROV3_PART(&pOpJoinProv3Part);
		}
	}
	else kprintf(L" <empty>\n");
}

void kuhl_m_misc_djoin_OP_CERT_PART_descr(DWORD level, ULONG cbBlob, PBYTE pBlob)
{
	POP_CERT_PART pOpCertPart = NULL;
	DWORD i;

	kprintf_level(L"[OP_CERT_PART]");
	if (cbBlob && pBlob)
	{
		kprintf(L"\n");
		if (kull_m_rpc_DecodeOP_CERT_PART(pBlob, cbBlob, &pOpCertPart))
		{
			level++;
			kprintf_level(L"cPfxStores: %u\n", pOpCertPart->cPfxStores);
			for (i = 0; i < pOpCertPart->cPfxStores; i++)
			{
				kprintf_level(L"[%u] PfxStore\n", i);
				kuhl_m_misc_djoin_OP_CERT_PFX_STORE_descr(level + 1, pOpCertPart->pPfxStores + i);
			}
			kprintf_level(L"cSstStores: %u\n", pOpCertPart->cSstStores);
			for (i = 0; i < pOpCertPart->cSstStores; i++)
			{
				kprintf_level(L"[%u] SstStore\n", i);
				kuhl_m_misc_djoin_OP_CERT_SST_STORE_descr(level + 1, pOpCertPart->pSstStores + i);
			}
			kprintf_level(L"Extension: 0x%p (%u)\n", pOpCertPart->Extension.pBlob, pOpCertPart->Extension.cbBlob);

			kull_m_rpc_FreeOP_CERT_PART(&pOpCertPart);
		}
	}
	else kprintf(L" <empty>\n");
}

void kuhl_m_misc_djoin_OP_CERT_PFX_STORE_descr(DWORD level, POP_CERT_PFX_STORE pPfxStore)
{
	kprintf_level(L"[OP_CERT_PFX_STORE]\n");
	level++;
	kprintf_level(L"pTemplateName           : %s\n", pPfxStore->pTemplateName);
	kprintf_level(L"ulPrivateKeyExportPolicy: 0x%08x\n", pPfxStore->ulPrivateKeyExportPolicy);
	kprintf_level(L"pPolicyServerUrl        : %s\n", pPfxStore->pPolicyServerUrl);
	kprintf_level(L"ulPolicyServerUrlFlags  : 0x%08x\n", pPfxStore->ulPolicyServerUrlFlags);
	kprintf_level(L"pPolicyServerId         : %s\n", pPfxStore->pPolicyServerId);
	kprintf_level(L"pfx          : %p (%u)\n", pPfxStore->pPfx, pPfxStore->cbPfx);
}

void kuhl_m_misc_djoin_OP_CERT_SST_STORE_descr(DWORD level, POP_CERT_SST_STORE pSstStore)
{
	kprintf_level(L"[OP_CERT_SST_STORE]\n");
	level++;
	kprintf_level(L"StoreLocation: 0x%08x (%s)\n", pSstStore->StoreLocation, kull_m_crypto_system_store_to_name(pSstStore->StoreLocation));
	kprintf_level(L"pStoreName   : %s\n", pSstStore->pStoreName);
	kprintf_level(L"sst          : %p (%u)\n", pSstStore->pSst, pSstStore->cbSst);
}

void kuhl_m_misc_djoin_OP_POLICY_PART_descr(DWORD level, ULONG cbBlob, PBYTE pBlob)
{
	POP_POLICY_PART pOpPolicyPart = NULL;
	DWORD i;

	kprintf_level(L"[OP_POLICY_PART]");
	if (cbBlob && pBlob)
	{
		kprintf(L"\n");
		if (kull_m_rpc_DecodeOP_POLICY_PART(pBlob, cbBlob, &pOpPolicyPart))
		{
			level++;
			kprintf_level(L"cElementLists: %u\n", pOpPolicyPart->cElementLists);
			for (i = 0; i < pOpPolicyPart->cElementLists; i++)
			{
				kprintf_level(L"[%u] ElementsList\n", i);
				kuhl_m_misc_djoin_OP_POLICY_ELEMENT_LIST_descr(level + 1, pOpPolicyPart->pElementLists + i);
			}
			kprintf_level(L"Extension    : 0x%p (%u)\n", pOpPolicyPart->Extension.pBlob, pOpPolicyPart->Extension.cbBlob);
			kull_m_rpc_FreeOP_POLICY_PART(&pOpPolicyPart);
		}
	}
	else kprintf(L" <empty>\n");
}

void kuhl_m_misc_djoin_OP_POLICY_ELEMENT_LIST_descr(DWORD level, POP_POLICY_ELEMENT_LIST pElementList)
{
	DWORD i;

	kprintf_level(L"[OP_POLICY_ELEMENT_LIST]\n");
	level++;
	kprintf_level(L"pSource    : %s\n", pElementList->pSource);
	kprintf_level(L"ulRootKeyId: 0x%08x\n", pElementList->ulRootKeyId);
	kprintf_level(L"cElements  : %u\n", pElementList->cElements);
	for (i = 0; i < pElementList->cElements; i++)
	{
		kprintf_level(L"[%u] Element\n", i);
		kuhl_m_misc_djoin_OP_POLICY_ELEMENT_descr(level + 1, pElementList->pElements + i);
	}
}

void kuhl_m_misc_djoin_OP_POLICY_ELEMENT_descr(DWORD level, POP_POLICY_ELEMENT pElement)
{
	kprintf_level(L"[OP_POLICY_ELEMENT]\n");
	level++;
	kprintf_level(L"pKeyPath   : %s\n", pElement->pKeyPath);
	kprintf_level(L"pValueName : %s\n", pElement->pValueName);
	kprintf_level(L"ulValueType: 0x%08x\n", pElement->ulValueType);
	kprintf_level(L"value      : ");
	switch (pElement->ulValueType)
	{
	case REG_SZ:
		kprintf(L"%s\n", pElement->pValueData);
		break;

	case REG_BINARY:
	default:
		kprintf(L"%p (%u)\n", pElement->pValueData, pElement->cbValueData);
		//kprinthex16(pElement->pValueData, pElement->cbValueData);
	}
}