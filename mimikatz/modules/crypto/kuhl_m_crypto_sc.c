/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_crypto_sc.h"

DWORD kuhl_m_crypto_l_sc_provtypefromname(LPCWSTR szProvider)
{
	DWORD result = 0, provType, tailleRequise, index = 0;
	wchar_t * monProvider;
	for(index = 0, result = 0; !result && CryptEnumProviders(index, NULL, 0, &provType, NULL, &tailleRequise); index++)
	{
		if(monProvider = (wchar_t *) LocalAlloc(LPTR, tailleRequise))
		{
			if(CryptEnumProviders(index, NULL, 0, &provType, monProvider, &tailleRequise))
				if(_wcsicmp(szProvider, monProvider) == 0)
					result = provType;
			LocalFree(monProvider);
		}
	}
	if(!result && GetLastError() != ERROR_NO_MORE_ITEMS)
		PRINT_ERROR_AUTO(L"CryptEnumProviders");
	return provType;
}

PWSTR kuhl_m_crypto_l_sc_containerFromReader(LPCWSTR reader)
{
	PWSTR result = NULL;
	DWORD szReader = (DWORD) wcslen(reader);
	if(result = (PWSTR) LocalAlloc(LPTR, (szReader + 6) * sizeof(wchar_t)))
	{
		RtlCopyMemory(result, L"\\\\.\\", 4 * sizeof(wchar_t));
		RtlCopyMemory(result + 4, reader, szReader * sizeof(wchar_t));
		RtlCopyMemory(result + 4 + szReader, L"\\", 1 * sizeof(wchar_t));
	}
	return result;
}

BOOL kuhl_m_crypto_l_sc_prop_tlv_features(SCARDHANDLE hCard, DWORD ctlCode)
{
	DWORD dwRet;
	BYTE data[256];
	LPCBYTE cur;
	LONG status;

	status = SCardControl(hCard, ctlCode, NULL, 0, data, sizeof(data), &dwRet);
	if(status == SCARD_S_SUCCESS)
	{
		for(cur = data; cur < (data + dwRet); cur += cur[1] + 2)
		{
			kprintf(L"    \\ %02x - ", cur[0], cur[1]);
			switch(cur[0])
			{
			case 1:
				if(cur[1] == sizeof(USHORT))
					kprintf(L"LCD Layout: %hhux%hhu\n", cur[2], cur[3]);
				break;
			case 2:
				if(cur[1] == sizeof(BYTE))
					kprintf(L"Entry Validation Condition: 0x%02x\n", cur[2]);
				break;
			case 3:
				if(cur[1] == sizeof(BYTE))
					kprintf(L"TimeOut2: %hhu\n", cur[2]);
				break;
			case 4:
				if(cur[1] == sizeof(USHORT))
					kprintf(L"LCD Max Characters: %hu\n", *(PUSHORT) (cur + 2));
				break;
			case 5:
				if(cur[1] == sizeof(USHORT))
					kprintf(L"LCD Max Lines: %hu\n", *(PUSHORT) (cur + 2));
				break;
			case 6:
				if(cur[1] == sizeof(BYTE))
					kprintf(L"Min Pin Size: %hhu\n", cur[2]);
				break;
			case 7:
				if(cur[1] == sizeof(BYTE))
					kprintf(L"Max Pin Size: %hhu\n", cur[2]);
				break;
			case 8:
				kprintf(L"FirmwareID: %.*S\n", cur[1], cur + 2);
				break;
			case 9:
				if(cur[1] == sizeof(BYTE))
				{
					kprintf(L"PPDU Support: %s", cur[2] ? L"YES" : L"NO");
					if(cur[2] & 1)
						kprintf(L" - SCardControl(FEATURE_CCID_ESC_COMMAND)");
					if(cur[2] & 2)
						kprintf(L" - SCardTransmit");
					kprintf(L"\n");
				}
				break;
			case 0x0a:
				if(cur[1] == sizeof(DWORD))
					kprintf(L"Max APDU Data Size: %u - 0x%x\n", *(PDWORD) (cur + 2), *(PDWORD) (cur + 2));
				break;
			case 0x0b:
				if(cur[1] == sizeof(USHORT))
					kprintf(L"USB VendorID : %04x\n", *(PUSHORT) (cur + 2));
				break;
			case 0x0c:
				if(cur[1] == sizeof(USHORT))
					kprintf(L"USB ProductID: %04x\n", *(PUSHORT) (cur + 2));
				break;

			default:
				kull_m_string_wprintf_hex(cur + 2, cur[1], 1);
				kprintf(L"\n");
			}
		}
	}
	else PRINT_ERROR(L"SCardControl(!FEATURE_GET_TLV_PROPERTIES!): 0x%08x (%u)\n", status, dwRet);
	return FALSE;
}

const ANSI_STRING
	OMNIKEY_STRING = {7, 8, "OMNIKEY"},
	ACS_STRING = {3, 4, "ACS"};
const PCWCHAR KUHL_M_CRYPTO_L_SC_PROP_FEATURES[] = {L"EXECUTE_PACE", L"VERIFY_PIN_START", L"VERIFY_PIN_FINISH", L"MODIFY_PIN_START", L"MODIFY_PIN_FINISH", L"GET_KEY_PRESSED", L"VERIFY_PIN_DIRECT", L"MODIFY_PIN_DIRECT", L"MCT_READER_DIRECT", L"MCT_UNIVERSAL", L"IFD_PIN_PROP", L"ABORT", L"SET_SPE_MESSAGE", L"VERIFY_PIN_DIRECT_APP_ID", L"MODIFY_PIN_DIRECT_APP_ID", L"WRITE_DISPLAY", L"GET_KEY", L"IFD_DISPLAY_PROPERTIES", L"GET_TLV_PROPERTIES", L"CCID_ESC_COMMAND",};
void kuhl_m_crypto_l_sc_prop(SCARDCONTEXT hContext, LPCWSTR reader)
{
	LONG status;
	SCARDHANDLE hCard;
	DWORD dwRet, dwVersion, i;
	KIWI_TLV_FEATURE features[255];
	PCWCHAR szFeature;
	ANSI_STRING aVendor, aModel;

	status = SCardConnect(hContext, reader, SCARD_SHARE_DIRECT, SCARD_PROTOCOL_UNDEFINED, &hCard, &dwRet);
	if(status == SCARD_S_SUCCESS)
	{
		dwRet = SCARD_AUTOALLOCATE;
		status = SCardGetAttrib(hCard, SCARD_ATTR_VENDOR_NAME, (PBYTE) &aVendor.Buffer, &dwRet);
		if(status == SCARD_S_SUCCESS)
		{
			if(!aVendor.Buffer[dwRet - 1])
				dwRet--;
			if(dwRet <= USHRT_MAX)
			{
				aVendor.Length = aVendor.MaximumLength = (USHORT) dwRet;
				kprintf(L"   | Vendor: %Z\n", &aVendor);
				dwRet = SCARD_AUTOALLOCATE;
				status = SCardGetAttrib(hCard, SCARD_ATTR_VENDOR_IFD_TYPE, (PBYTE) &aModel.Buffer, &dwRet);
				if(status == SCARD_S_SUCCESS)
				{
					if(!aModel.Buffer[dwRet - 1])
						dwRet--;
					if(dwRet <= USHRT_MAX)
					{
						aModel.Length = aModel.MaximumLength = (USHORT) dwRet;
						kprintf(L"   | Model : %Z\n", &aModel);

						if(RtlEqualString(&aVendor, &OMNIKEY_STRING, TRUE))
						{
							status = SCardControl(hCard, CM_IOCTL_GET_FW_VERSION, NULL, 0, &dwVersion, sizeof(DWORD), &dwRet);
							if((status == SCARD_S_SUCCESS) && (dwRet == sizeof(DWORD)))
								kprintf(L"   | FW version : %u.%02u\n", dwVersion / 100, dwVersion % 100);
							else PRINT_ERROR(L"SCardControl(CM_IOCTL_GET_FW_VERSION): 0x%08x (%u)\n", status, dwRet);

							status = SCardControl(hCard, CM_IOCTL_GET_LIB_VERSION, NULL, 0, &dwVersion, sizeof(DWORD), &dwRet);
							if((status == SCARD_S_SUCCESS) && (dwRet == sizeof(DWORD)))
								kprintf(L"   | Lib version: %u.%02u\n", dwVersion / 100, dwVersion % 100);
							else PRINT_ERROR(L"SCardControl(CM_IOCTL_GET_LIB_VERSION): 0x%08x (%u)\n", status, dwRet);
						}
						else
						{

						}
					}
					SCardFreeMemory(hContext, aModel.Buffer);
				}
			}
			SCardFreeMemory(hContext, aVendor.Buffer);
		}

		status = SCardControl(hCard, IOCTL_GET_FEATURE_REQUEST, NULL, 0, features, sizeof(features), &dwRet);
		if((status == SCARD_S_SUCCESS) && dwRet)
		{
			kprintf(L"   | Features:\n");
			for(i = 0; i < (dwRet / sizeof(KIWI_TLV_FEATURE)); i++)
			{
				kprintf(L"   \\ ");
				if(features[i].Length == sizeof(DWORD))
				{
					dwVersion = (_byteswap_ulong(features[i].ControlCode) >> 2) & 0xfff;

					if((features[i].Tag >= FEATURE_VERIFY_PIN_START) && (features[i].Tag <= FEATURE_CCID_ESC_COMMAND))
						szFeature = KUHL_M_CRYPTO_L_SC_PROP_FEATURES[features[i].Tag];
					else if(features[i].Tag == FEATURE_EXECUTE_PACE)
						szFeature = KUHL_M_CRYPTO_L_SC_PROP_FEATURES[0];
					else szFeature = L"?";

					kprintf(L"%02x - %s (%u)\n", features[i].Tag, szFeature, dwVersion);
					if(features[i].Tag == FEATURE_GET_TLV_PROPERTIES)
						kuhl_m_crypto_l_sc_prop_tlv_features(hCard, SCARD_CTL_CODE(dwVersion));
				}
				else
				{
					PRINT_ERROR(L"Length (%hhu) != sizeof(DWORD)\n", features[i].Length);
					break;
				}
			}
		}
		SCardDisconnect(hCard, SCARD_LEAVE_CARD);
	}
	else PRINT_ERROR(L"SCardConnect: 0x%08x\n", status);
}

NTSTATUS kuhl_m_crypto_l_sc(int argc, wchar_t * argv[])
{
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	PBYTE atr;
	LONG status;
	LPWSTR mszReaders = NULL, pReader, mszCards = NULL, pCard, szProvider = NULL, szContainer;
	DWORD dwLen = SCARD_AUTOALLOCATE, dwAtrLen;

	status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if(status == SCARD_S_SUCCESS)
	{
		status = SCardListReaders(hContext, SCARD_ALL_READERS, (LPWSTR) &mszReaders, &dwLen);
		if(status == SCARD_S_SUCCESS)
		{
			kprintf(L"SmartCard readers:");
			for(pReader = mszReaders; *pReader; pReader += wcslen(pReader) + 1)
			{
				kprintf(L"\n * %s\n", pReader);
				kuhl_m_crypto_l_sc_prop(hContext, pReader);
				if(szContainer = kuhl_m_crypto_l_sc_containerFromReader(pReader))
				{
					status = SCardConnect(hContext, pReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwLen);
					if(status == SCARD_S_SUCCESS)
					{
						dwAtrLen = SCARD_AUTOALLOCATE;
						status = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, (PBYTE) &atr, &dwAtrLen);
						if(status == SCARD_S_SUCCESS)
						{
							kprintf(L"   ATR  : ");
							kull_m_string_wprintf_hex(atr, dwAtrLen, 0);
							kprintf(L"\n");
							dwLen = SCARD_AUTOALLOCATE;
							status = SCardListCards(hContext, atr, NULL, 0, (LPWSTR) &mszCards, &dwLen);
							if(status == SCARD_S_SUCCESS)
							{
								for(pCard = mszCards; pCard && *pCard; pCard += wcslen(pCard) + 1)
								{
									kprintf(L"   Model: %s\n", pCard);

									dwLen = SCARD_AUTOALLOCATE;
									status = SCardGetCardTypeProviderName(hContext, pCard, SCARD_PROVIDER_PRIMARY, (LPWSTR) &szProvider, &dwLen);
									if(status == SCARD_S_SUCCESS)
									{
										kprintf(L"   PRIM : %s\n", szProvider);
										SCardFreeMemory(hContext, szProvider);
									}
									else if(status != ERROR_FILE_NOT_FOUND) PRINT_ERROR(L"SCardGetCardTypeProviderName(PRIM): 0x%08x\n", status);

									dwLen = SCARD_AUTOALLOCATE;
									status = SCardGetCardTypeProviderName(hContext, pCard, SCARD_PROVIDER_CSP, (LPWSTR) &szProvider, &dwLen);
									if(status == SCARD_S_SUCCESS)
									{
										kprintf(L"   CSP  : %s\n", szProvider);
										if(dwLen = kuhl_m_crypto_l_sc_provtypefromname(szProvider))
											kuhl_m_crypto_l_keys_capi(szContainer, szProvider, dwLen, CRYPT_SILENT, FALSE, NULL);
										SCardFreeMemory(hContext, szProvider);
									}
									else if(status != ERROR_FILE_NOT_FOUND) PRINT_ERROR(L"SCardGetCardTypeProviderName(CSP): 0x%08x\n", status);

									dwLen = SCARD_AUTOALLOCATE;
									status = SCardGetCardTypeProviderName(hContext, pCard, SCARD_PROVIDER_KSP, (LPWSTR) &szProvider, &dwLen);
									if(status == SCARD_S_SUCCESS)
									{
										kprintf(L"   KSP  : %s\n", szProvider);
										kuhl_m_crypto_l_keys_cng(szContainer, szProvider, 0, FALSE, NULL);
										SCardFreeMemory(hContext, szProvider);
									}
									else if(status != ERROR_FILE_NOT_FOUND) PRINT_ERROR(L"SCardGetCardTypeProviderName(KSP): 0x%08x\n", status);

									dwLen = SCARD_AUTOALLOCATE;
									status = SCardGetCardTypeProviderName(hContext, pCard, SCARD_PROVIDER_CARD_MODULE, (LPWSTR) &szProvider, &dwLen);
									if(status == SCARD_S_SUCCESS)
									{
										kprintf(L"   MDRV : %s\n", szProvider);
										kuhl_m_crypto_l_mdr(szProvider, hContext, hCard, pCard, atr, dwAtrLen);
										SCardFreeMemory(hContext, szProvider);
									}
									else if(status != ERROR_FILE_NOT_FOUND) PRINT_ERROR(L"SCardGetCardTypeProviderName(MDR): 0x%08x\n", status);
								}
								SCardFreeMemory(hContext, mszCards);
							}
							else PRINT_ERROR(L"SCardListCards: 0x%08x\n", status);
							SCardFreeMemory(hContext, atr);
						}
						else PRINT_ERROR(L"SCardGetAttrib: 0x%08x (%u)\n", status, dwAtrLen);
						SCardDisconnect(hCard, SCARD_LEAVE_CARD);
					}
					else if(status != SCARD_W_REMOVED_CARD)
						PRINT_ERROR(L"SCardConnect: 0x%08x\n", status);
					LocalFree(szContainer);
				}
			}
			SCardFreeMemory(hContext, mszReaders);
		}
		else PRINT_ERROR(L"SCardListReaders: 0x%08x\n", status);
		SCardReleaseContext(hContext);
	}
	else PRINT_ERROR(L"SCardEstablishContext: 0x%08x\n", status);
	return STATUS_SUCCESS;
}




LPVOID WINAPI mdAlloc(__in SIZE_T Size)
{
	return malloc(Size);
}

LPVOID WINAPI mdReAlloc( __in LPVOID Address, __in SIZE_T Size)
{
	return realloc(Address, Size);
}

void WINAPI mdFree( __in LPVOID Address)
{
	if(Address)
		free(Address);
}

DWORD WINAPI mdCacheAddFile(__in PVOID pvCacheContext, __in LPWSTR wszTag, __in DWORD dwFlags, __in_bcount(cbData) PBYTE pbData, __in DWORD cbData)
{
	kprintf(TEXT(__FUNCTION__) L"\n");
	return SCARD_E_INVALID_PARAMETER;
}

DWORD WINAPI mdCacheLookupFile(__in PVOID pvCacheContext, __in LPWSTR wszTag, __in DWORD dwFlags, __deref_out_bcount(*pcbData) PBYTE *ppbData, __out PDWORD pcbData)
{
	kprintf(TEXT(__FUNCTION__) L"\n");
	return SCARD_E_INVALID_PARAMETER;
}

DWORD WINAPI mdCacheDeleteFile(__in PVOID pvCacheContext, __in LPWSTR wszTag, __in DWORD dwFlags)
{
	kprintf(TEXT(__FUNCTION__) L"\n");
	return SCARD_E_INVALID_PARAMETER;
}

DWORD WINAPI mdPadData(__in PCARD_SIGNING_INFO  pSigningInfo, __in DWORD cbMaxWidth, __out DWORD* pcbPaddedBuffer, __deref_out_bcount(*pcbPaddedBuffer) PBYTE* ppbPaddedBuffer)
{
	kprintf(TEXT(__FUNCTION__) L"\n");
	return SCARD_E_INVALID_PARAMETER;
}

void enuma(PCARD_DATA pData, LPCSTR dir)
{
	LPSTR files = NULL, p;
	DWORD status, nFiles = 0;
	
	kprintf(L"    \\%-8S: ", dir ? dir : "<root>");
	status = pData->pfnCardEnumFiles(pData, (LPSTR) dir, &files, &nFiles, 0);
	if(status == SCARD_S_SUCCESS)
	{
		for(p = files; *p; p += lstrlenA(p) + 1)
			kprintf(L"%S ; ", p);
		kprintf(L"\n");
		pData->pfnCspFree(files);
	}
	else if(status == SCARD_E_FILE_NOT_FOUND)
		kprintf(L"<empty>\n");
	else PRINT_ERROR(L"CardEnumFiles: 0x%08x\n", status);
}

void descblob(PUBLICKEYSTRUC *pk)
{
	kprintf(L"%s", kull_m_crypto_algid_to_name(pk->aiKeyAlg));
	switch(pk->aiKeyAlg)
	{
	case CALG_RSA_KEYX:
	case CALG_RSA_SIGN:
		kprintf(L" (%u)", ((PRSA_GENERICKEY_BLOB) pk)->RsaKey.bitlen);
		break;
	default:
		;
	}
}

void kuhl_m_crypto_l_mdr(LPCWSTR szMdr, SCARDCONTEXT ctxScard, SCARDHANDLE hScard, LPCWSTR szModel, LPCBYTE pbAtr, DWORD cbAtr)
{
	HMODULE hModule;
	CARD_DATA cd = {0};
	PFN_CARD_ACQUIRE_CONTEXT CardAcquireContext;
	//CARD_CAPABILITIES cap = {CARD_CAPABILITIES_CURRENT_VERSION, FALSE, FALSE};
	CARD_FREE_SPACE_INFO spa = {CARD_FREE_SPACE_INFO_CURRENT_VERSION, 0, 0, 0};
	CONTAINER_INFO ci;
	DWORD status, i;

	if(hModule = LoadLibrary(szMdr))
	{
		if(CardAcquireContext = (PFN_CARD_ACQUIRE_CONTEXT) GetProcAddress(hModule, "CardAcquireContext"))
		{
			cd.dwVersion = CARD_DATA_CURRENT_VERSION; // 7
			cd.pbAtr = (PBYTE) pbAtr;
			cd.cbAtr = cbAtr;
			cd.pwszCardName = (LPWSTR) szModel;

			cd.pfnCspAlloc = mdAlloc;
			cd.pfnCspReAlloc = mdReAlloc;
			cd.pfnCspFree = mdFree;
			cd.pfnCspCacheAddFile = mdCacheAddFile;
			cd.pfnCspCacheLookupFile = mdCacheLookupFile;
			cd.pfnCspCacheDeleteFile = mdCacheDeleteFile;
			cd.pfnCspPadData = mdPadData;
			
			cd.hSCardCtx = ctxScard;
			cd.hScard = hScard;

			cd.pfnCspGetDHAgreement = NULL;
			cd.pfnCspUnpadData = NULL;


			status = CardAcquireContext(&cd, 0);
			if(status == SCARD_S_SUCCESS)
			{
				//status = cd.pfnCardQueryCapabilities(&cd, &cap);
				//if(status == SCARD_S_SUCCESS)
				//	kprintf(L"    CertificateCompression: %08x\n    KeyGen: %08x\n", cap.fCertificateCompression, cap.fKeyGen);
				//else PRINT_ERROR(L"CardQueryCapabilities: 0x%08x\n", status);

				status = cd.pfnCardQueryFreeSpace(&cd, 0, &spa);
				if(status == SCARD_S_SUCCESS)
				{
					kprintf(L"    Containers: %u / %u (%u byte(s) free)\n", spa.dwKeyContainersAvailable, spa.dwMaxKeyContainers, spa.dwBytesAvailable);

					for(i = 0; i < spa.dwMaxKeyContainers; i++)
					{
						ci.dwVersion = CONTAINER_INFO_CURRENT_VERSION;
						status = cd.pfnCardGetContainerInfo(&cd, (BYTE) i, 0, &ci);
						if(status == SCARD_S_SUCCESS)
						{
							kprintf(L"\t[%2u] ", i);
							if(ci.cbSigPublicKey && ci.pbSigPublicKey)
							{
								kprintf(L"Signature: ");
								descblob((PUBLICKEYSTRUC *) ci.pbSigPublicKey);
								cd.pfnCspFree(ci.pbSigPublicKey);

								if(ci.cbKeyExPublicKey && ci.pbKeyExPublicKey)
									kprintf(L" - ");
							}
							if(ci.cbKeyExPublicKey && ci.pbKeyExPublicKey)
							{
								kprintf(L"Exchange: ");
								descblob((PUBLICKEYSTRUC *) ci.pbKeyExPublicKey);
								cd.pfnCspFree(ci.pbKeyExPublicKey);
							}
							kprintf(L"\n");
						}
						else if(status != SCARD_E_NO_KEY_CONTAINER) PRINT_ERROR(L"CardGetContainerInfo(%u): 0x%08x\n", i, status);
					}
				}
				else PRINT_ERROR(L"CardQueryFreeSpace: 0x%08x\n", status);

				enuma(&cd, NULL);
				enuma(&cd, "mscp");
				enuma(&cd, "mimikatz");
				


				status = cd.pfnCardDeleteContext(&cd);
				if(status != SCARD_S_SUCCESS)
					PRINT_ERROR(L"CardDeleteContext: 0x%08x\n", status);
			}
			else PRINT_ERROR(L"CardAcquireContext: 0x%08x\n", status);

		}
		else PRINT_ERROR(L"No CardAcquireContext export in \'%s\'\n", szMdr);
		FreeLibrary(hModule);
	}
	else PRINT_ERROR_AUTO(L"LoadLibrary");
}